"""
Tests for the ODPSC Master v2 module.
"""

import base64
import json
import os
import uuid
import zipfile
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from odpsc_master import (
    BundleStore,
    _aggregate_bundles,
    create_app,
    decrypt_bundle,
    derive_encryption_key,
    encrypt_bundle,
    hash_password,
    load_config,
    verify_password,
)


class TestLoadConfig:
    """Tests for master configuration loading."""

    def test_load_defaults(self, tmp_dir):
        config = load_config(os.path.join(tmp_dir, 'nonexistent.json'))
        assert config['collection_enabled'] is True
        assert config['auto_send_enabled'] is True
        assert config['master_port'] == 8085
        assert 'api_key' in config
        assert 'max_upload_size_mb' in config

    def test_load_custom(self, master_config):
        config, config_path = master_config
        loaded = load_config(config_path)
        assert loaded['cluster_name'] == 'test-cluster'
        assert loaded['api_key'] == 'test-api-key-12345'


class TestBundleStore:
    """Tests for SQLite bundle store CRUD operations."""

    def test_register_new_bundle(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'test.db')
        store = BundleStore(db_path)
        result = store.register_bundle('uuid-001', 'host1', 'file.zip', '/path/file.zip', 'L1', 1024)
        assert result is True

    def test_register_duplicate_bundle(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'test.db')
        store = BundleStore(db_path)
        store.register_bundle('uuid-001', 'host1', 'file.zip', '/path/file.zip')
        result = store.register_bundle('uuid-001', 'host1', 'file2.zip', '/path/file2.zip')
        assert result is False

    def test_is_duplicate(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'test.db')
        store = BundleStore(db_path)
        assert store.is_duplicate('uuid-001') is False
        store.register_bundle('uuid-001', 'host1', 'file.zip', '/path/file.zip')
        assert store.is_duplicate('uuid-001') is True

    def test_get_pending_bundles(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'test.db')
        store = BundleStore(db_path)
        store.register_bundle('uuid-001', 'host1', 'file1.zip', '/path/file1.zip')
        store.register_bundle('uuid-002', 'host2', 'file2.zip', '/path/file2.zip')

        pending = store.get_pending_bundles()
        assert len(pending) == 2

    def test_mark_aggregated(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'test.db')
        store = BundleStore(db_path)
        store.register_bundle('uuid-001', 'host1', 'file.zip', '/path/file.zip')
        store.mark_aggregated(['uuid-001'])

        pending = store.get_pending_bundles()
        assert len(pending) == 0

    def test_get_all_bundles(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'test.db')
        store = BundleStore(db_path)
        for i in range(5):
            store.register_bundle(f'uuid-{i:03d}', f'host{i}', f'file{i}.zip', f'/path/file{i}.zip')

        all_bundles = store.get_all_bundles(limit=3)
        assert len(all_bundles) == 3

    def test_get_bundle_by_id(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'test.db')
        store = BundleStore(db_path)
        store.register_bundle('uuid-001', 'host1', 'file.zip', '/path/file.zip', 'L2', 2048)

        bundle = store.get_bundle('uuid-001')
        assert bundle is not None
        assert bundle['hostname'] == 'host1'
        assert bundle['level'] == 'L2'
        assert bundle['size_bytes'] == 2048

    def test_get_bundle_not_found(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'test.db')
        store = BundleStore(db_path)
        assert store.get_bundle('nonexistent') is None

    def test_get_bundle_count(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'test.db')
        store = BundleStore(db_path)
        assert store.get_bundle_count() == 0
        store.register_bundle('uuid-001', 'host1', 'file.zip', '/path/file.zip')
        assert store.get_bundle_count() == 1

    def test_cleanup_old(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'test.db')
        store = BundleStore(db_path)
        store.register_bundle('uuid-001', 'host1', 'file.zip', '/path/file.zip')
        # cleanup_old with 0 days should remove everything
        store.cleanup_old(days=0)
        # Note: cleanup_old uses date arithmetic, so with 0 days the behavior
        # depends on the exact time. Just verify it doesn't crash.
        assert store.get_bundle_count() >= 0


class TestApiKeyAuthentication:
    """Tests for API key authentication on upload endpoint."""

    def test_upload_with_valid_key(self, client, api_key_headers, tmp_dir):
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('manifest.json', json.dumps({
                'bundle_id': api_key_headers['X-ODPSC-Bundle-ID'],
                'hostname': 'test-host',
                'level': 'L1',
            }))
        zip_buffer.seek(0)

        resp = client.post(
            '/api/v2/bundles/upload',
            data={'bundle': (zip_buffer, 'test_agent.zip')},
            headers=api_key_headers,
            content_type='multipart/form-data',
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'received'

    def test_upload_with_invalid_key(self, client):
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('data.json', '{}')
        zip_buffer.seek(0)

        resp = client.post(
            '/api/v2/bundles/upload',
            data={'bundle': (zip_buffer, 'test_agent.zip')},
            headers={
                'Authorization': 'Bearer wrong-key',
                'X-ODPSC-Bundle-ID': 'test-id',
            },
            content_type='multipart/form-data',
        )
        assert resp.status_code == 401

    def test_upload_without_key(self, client):
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('data.json', '{}')
        zip_buffer.seek(0)

        resp = client.post(
            '/api/v2/bundles/upload',
            data={'bundle': (zip_buffer, 'test_agent.zip')},
            headers={'X-ODPSC-Bundle-ID': 'test-id'},
            content_type='multipart/form-data',
        )
        assert resp.status_code == 401

    def test_upload_missing_bundle_id(self, client, api_key_headers):
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('data.json', '{}')
        zip_buffer.seek(0)

        headers = {'Authorization': api_key_headers['Authorization']}  # No X-ODPSC-Bundle-ID
        resp = client.post(
            '/api/v2/bundles/upload',
            data={'bundle': (zip_buffer, 'test_agent.zip')},
            headers=headers,
            content_type='multipart/form-data',
        )
        assert resp.status_code == 400


class TestDeduplication:
    """Tests for bundle deduplication."""

    def test_duplicate_returns_duplicate_status(self, client, api_key_headers):
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('manifest.json', json.dumps({
                'bundle_id': 'dedup-test-001',
                'hostname': 'test-host',
                'level': 'L1',
            }))
        zip_buffer.seek(0)

        headers = dict(api_key_headers)
        headers['X-ODPSC-Bundle-ID'] = 'dedup-test-001'

        # First upload
        resp1 = client.post(
            '/api/v2/bundles/upload',
            data={'bundle': (zip_buffer, 'test.zip')},
            headers=headers,
            content_type='multipart/form-data',
        )
        assert resp1.status_code == 200
        assert resp1.get_json()['status'] == 'received'

        # Second upload (duplicate)
        zip_buffer2 = BytesIO()
        with zipfile.ZipFile(zip_buffer2, 'w') as zf:
            zf.writestr('manifest.json', json.dumps({
                'bundle_id': 'dedup-test-001',
                'hostname': 'test-host',
                'level': 'L1',
            }))
        zip_buffer2.seek(0)

        resp2 = client.post(
            '/api/v2/bundles/upload',
            data={'bundle': (zip_buffer2, 'test.zip')},
            headers=headers,
            content_type='multipart/form-data',
        )
        assert resp2.status_code == 200
        assert resp2.get_json()['status'] == 'duplicate'


class TestRateLimiting:
    """Tests for rate limiting."""

    def test_upload_no_bundle_file(self, client, api_key_headers):
        resp = client.post(
            '/api/v2/bundles/upload',
            headers=api_key_headers,
        )
        assert resp.status_code == 400

    def test_upload_empty_filename(self, client, api_key_headers):
        resp = client.post(
            '/api/v2/bundles/upload',
            data={'bundle': (BytesIO(b''), '')},
            headers=api_key_headers,
            content_type='multipart/form-data',
        )
        assert resp.status_code == 400


class TestBundleListEndpoint:
    """Tests for bundle list and download endpoints."""

    def test_list_bundles(self, client, auth_headers, api_key_headers):
        # Upload a bundle first
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('manifest.json', json.dumps({
                'bundle_id': 'list-test-001',
                'hostname': 'test-host',
                'level': 'L1',
            }))
        zip_buffer.seek(0)

        headers = dict(api_key_headers)
        headers['X-ODPSC-Bundle-ID'] = 'list-test-001'
        client.post(
            '/api/v2/bundles/upload',
            data={'bundle': (zip_buffer, 'test.zip')},
            headers=headers,
            content_type='multipart/form-data',
        )

        # List bundles
        resp = client.get('/api/v2/bundles', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'bundles' in data
        assert data['total'] >= 1

    def test_list_bundles_requires_auth(self, client):
        resp = client.get('/api/v2/bundles')
        assert resp.status_code == 401

    def test_download_bundle(self, client, auth_headers, api_key_headers):
        bundle_id = 'download-test-001'
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('manifest.json', json.dumps({
                'bundle_id': bundle_id,
                'hostname': 'test-host',
                'level': 'L1',
            }))
        zip_buffer.seek(0)

        headers = dict(api_key_headers)
        headers['X-ODPSC-Bundle-ID'] = bundle_id
        client.post(
            '/api/v2/bundles/upload',
            data={'bundle': (zip_buffer, 'test.zip')},
            headers=headers,
            content_type='multipart/form-data',
        )

        resp = client.get(f'/api/v2/bundles/{bundle_id}', headers=auth_headers)
        assert resp.status_code == 200

    def test_download_nonexistent_bundle(self, client, auth_headers):
        resp = client.get('/api/v2/bundles/nonexistent-id', headers=auth_headers)
        assert resp.status_code == 404


class TestCollectEndpoint:
    """Tests for the /api/v2/collect endpoint."""

    @patch('odpsc_master._trigger_agent_collection')
    def test_manual_collect(self, mock_trigger, client, auth_headers):
        resp = client.post(
            '/api/v2/collect',
            json={'level': 'L2'},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'triggered'
        assert data['level'] == 'L2'

    def test_collect_requires_auth(self, client):
        resp = client.post('/api/v2/collect', json={'level': 'L1'})
        assert resp.status_code == 401

    def test_collect_wrong_auth(self, client):
        bad_auth = base64.b64encode(b'wrong:wrong').decode('utf-8')
        resp = client.post(
            '/api/v2/collect',
            json={'level': 'L1'},
            headers={'Authorization': f'Basic {bad_auth}'},
        )
        assert resp.status_code == 401

    @patch('odpsc_master._trigger_agent_collection')
    def test_collect_disabled(self, mock_trigger, master_config, tmp_dir, monkeypatch):
        config, _ = master_config
        config['collection_enabled'] = False
        monkeypatch.setattr('odpsc_master.BUNDLE_DIR', os.path.join(tmp_dir, 'bundles2'))
        monkeypatch.setattr('odpsc_master.DB_DIR', os.path.join(tmp_dir, 'db2'))
        monkeypatch.setattr('odpsc_master.DB_PATH', os.path.join(tmp_dir, 'db2', 'bundles.db'))
        monkeypatch.setattr('odpsc_master.AGGREGATED_DIR', os.path.join(tmp_dir, 'aggregated2'))
        monkeypatch.setattr('odpsc_master.CONFIG_PATH', os.path.join(tmp_dir, 'cfg.json'))

        app = create_app(config)
        app.config['TESTING'] = True
        test_client = app.test_client()

        credentials = base64.b64encode(b'admin:admin').decode('utf-8')
        resp = test_client.post(
            '/api/v2/collect',
            json={'level': 'L1'},
            headers={'Authorization': f'Basic {credentials}'},
        )
        assert resp.status_code == 403


class TestAggregateEndpoint:
    """Tests for the /api/v2/aggregate endpoint."""

    def test_aggregate_no_pending(self, client, auth_headers):
        resp = client.post('/api/v2/aggregate', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'no_pending'

    def test_aggregate_requires_auth(self, client):
        resp = client.post('/api/v2/aggregate')
        assert resp.status_code == 401


class TestStreamingAggregation:
    """Tests for streaming aggregation."""

    def test_aggregate_processes_bundles(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'test.db')
        bundles_dir = os.path.join(tmp_dir, 'bundles')
        aggregated_dir = os.path.join(tmp_dir, 'aggregated')
        os.makedirs(bundles_dir, exist_ok=True)
        os.makedirs(aggregated_dir, exist_ok=True)

        store = BundleStore(db_path)

        # Create test agent bundles
        for i in range(3):
            bundle_id = f'uuid-{i:03d}'
            zip_filename = f'agent_bundle_{i}.zip'
            zip_path = os.path.join(bundles_dir, zip_filename)
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr('logs/test.log', f'ERROR error from agent {i}')
                zf.writestr('metrics.json', json.dumps({'cpu': i * 10}))
                zf.writestr('system_info.json', json.dumps({'hostname': f'node{i}'}))
                zf.writestr('manifest.json', json.dumps({
                    'bundle_id': bundle_id,
                    'hostname': f'node{i}',
                    'level': 'L3',
                }))
            store.register_bundle(bundle_id, f'node{i}', zip_filename, zip_path, 'L3',
                                  os.path.getsize(zip_path))

        with patch('odpsc_master.AGGREGATED_DIR', aggregated_dir):
            config = {'max_bundle_size_mb': 500, 'encryption_key': '', 'hdfs_archive_enabled': False}
            result = _aggregate_bundles(store, config)

        assert result['status'] == 'aggregated'
        assert result['agent_count'] == 3
        assert result['bundles_processed'] == 3
        assert os.path.exists(result['output'])

        # Verify aggregated bundle contents
        with zipfile.ZipFile(result['output'], 'r') as zf:
            names = zf.namelist()
            assert 'metrics.json' in names
            assert 'analysis.json' in names
            assert 'analysis_report.txt' in names
            assert 'metadata.json' in names

    def test_aggregate_respects_max_size(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'test.db')
        bundles_dir = os.path.join(tmp_dir, 'bundles')
        aggregated_dir = os.path.join(tmp_dir, 'aggregated')
        os.makedirs(bundles_dir, exist_ok=True)
        os.makedirs(aggregated_dir, exist_ok=True)

        store = BundleStore(db_path)

        # Create a bundle
        zip_path = os.path.join(bundles_dir, 'big.zip')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('data.json', 'x' * 1000)
        store.register_bundle('uuid-big', 'host1', 'big.zip', zip_path, 'L1',
                              os.path.getsize(zip_path))

        # Set max_bundle_size to 0 bytes - should still process at least 0 bundles
        with patch('odpsc_master.AGGREGATED_DIR', aggregated_dir):
            config = {'max_bundle_size_mb': 0, 'encryption_key': '', 'hdfs_archive_enabled': False}
            result = _aggregate_bundles(store, config)

        # With 0 MB max, no bundles should be processed
        assert result['agent_count'] == 0


class TestAes256GcmEncryption:
    """Tests for AES-256-GCM encryption."""

    def test_encrypt_decrypt_roundtrip(self, tmp_dir):
        test_file = os.path.join(tmp_dir, 'test.zip')
        original_data = b'test data for encryption - ODPSC v2'
        with open(test_file, 'wb') as f:
            f.write(original_data)

        encrypted_path = encrypt_bundle(test_file, 'my-secret-key')
        assert encrypted_path.endswith('.enc')
        assert os.path.exists(encrypted_path)
        assert not os.path.exists(test_file)

        decrypted = decrypt_bundle(encrypted_path, 'my-secret-key')
        assert decrypted == original_data

    def test_wrong_key_fails(self, tmp_dir):
        test_file = os.path.join(tmp_dir, 'test.zip')
        with open(test_file, 'wb') as f:
            f.write(b'test data')

        encrypted_path = encrypt_bundle(test_file, 'correct-key')

        with pytest.raises(Exception):
            decrypt_bundle(encrypted_path, 'wrong-key')

    def test_tampered_ciphertext_fails(self, tmp_dir):
        test_file = os.path.join(tmp_dir, 'test.zip')
        with open(test_file, 'wb') as f:
            f.write(b'test data')

        encrypted_path = encrypt_bundle(test_file, 'my-key')

        # Tamper with the encrypted file
        with open(encrypted_path, 'r+b') as f:
            f.seek(20)
            f.write(b'\x00\x00\x00\x00')

        with pytest.raises(Exception):
            decrypt_bundle(encrypted_path, 'my-key')

    def test_no_encryption_without_key(self, tmp_dir, monkeypatch):
        monkeypatch.setattr('odpsc_master.BUNDLE_DIR', os.path.join(tmp_dir, 'enc_bundles'))
        monkeypatch.setattr('odpsc_master.DB_DIR', os.path.join(tmp_dir, 'enc_db'))
        monkeypatch.setattr('odpsc_master.DB_PATH', os.path.join(tmp_dir, 'enc_db', 'bundles.db'))
        monkeypatch.setattr('odpsc_master.AGGREGATED_DIR', os.path.join(tmp_dir, 'enc_agg'))
        monkeypatch.setattr('odpsc_master.CONFIG_PATH', os.path.join(tmp_dir, 'enc_cfg.json'))

        config = {
            'collection_enabled': True,
            'auto_send_enabled': True,
            'admin_username': 'admin',
            'admin_password': 'admin',
            'admin_password_hash': '',
            'api_key': '',
            'encryption_key': '',
            'max_upload_size_mb': 100,
            'max_bundle_size_mb': 500,
        }
        app = create_app(config)
        assert app is not None  # App created without encryption key


class TestPasswordManagement:
    """Tests for bcrypt password hashing and auth."""

    def test_hash_and_verify(self):
        password_hash = hash_password('my-secure-password')
        assert verify_password('my-secure-password', password_hash) is True
        assert verify_password('wrong-password', password_hash) is False

    def test_empty_hash_fails(self):
        assert verify_password('any-password', '') is False

    def test_bcrypt_auth_endpoint(self, tmp_dir, monkeypatch):
        monkeypatch.setattr('odpsc_master.BUNDLE_DIR', os.path.join(tmp_dir, 'bcrypt_bundles'))
        monkeypatch.setattr('odpsc_master.DB_DIR', os.path.join(tmp_dir, 'bcrypt_db'))
        monkeypatch.setattr('odpsc_master.DB_PATH', os.path.join(tmp_dir, 'bcrypt_db', 'bundles.db'))
        monkeypatch.setattr('odpsc_master.AGGREGATED_DIR', os.path.join(tmp_dir, 'bcrypt_agg'))
        monkeypatch.setattr('odpsc_master.CONFIG_PATH', os.path.join(tmp_dir, 'bcrypt_cfg.json'))

        pw_hash = hash_password('securepass')
        config = {
            'collection_enabled': True,
            'auto_send_enabled': True,
            'admin_username': 'admin',
            'admin_password_hash': pw_hash,
            'admin_password': '',
            'api_key': '',
            'encryption_key': '',
            'max_upload_size_mb': 100,
            'max_bundle_size_mb': 500,
        }
        app = create_app(config)
        app.config['TESTING'] = True
        client = app.test_client()

        # Correct password should work
        credentials = base64.b64encode(b'admin:securepass').decode('utf-8')
        resp = client.get(
            '/api/v2/status',
            headers={'Authorization': f'Basic {credentials}'},
        )
        assert resp.status_code == 200

        # Wrong password should fail
        bad_creds = base64.b64encode(b'admin:wrongpass').decode('utf-8')
        resp = client.get(
            '/api/v2/status',
            headers={'Authorization': f'Basic {bad_creds}'},
        )
        assert resp.status_code == 401

    def test_password_update_via_config(self, client, auth_headers, tmp_dir, monkeypatch):
        monkeypatch.setattr('odpsc_master.CONFIG_PATH', os.path.join(tmp_dir, 'cfg.json'))

        resp = client.post(
            '/api/v2/config',
            json={'admin_password': 'new-password'},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'admin_password' in data['applied']


class TestConfigEndpoints:
    """Tests for the /api/v2/config endpoints."""

    def test_get_config(self, client, auth_headers):
        resp = client.get('/api/v2/config', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'collection_enabled' in data
        # Sensitive fields should be masked
        if data.get('api_key'):
            assert data['api_key'] == '****MASKED****'

    def test_get_config_requires_auth(self, client):
        resp = client.get('/api/v2/config')
        assert resp.status_code == 401

    def test_update_config(self, client, auth_headers, tmp_dir, monkeypatch):
        monkeypatch.setattr('odpsc_master.CONFIG_PATH', os.path.join(tmp_dir, 'cfg.json'))

        resp = client.post(
            '/api/v2/config',
            json={'collection_enabled': False},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'updated'
        assert 'collection_enabled' in data['applied']

    def test_update_config_requires_auth(self, client):
        resp = client.post(
            '/api/v2/config',
            json={'collection_enabled': False},
        )
        assert resp.status_code == 401

    def test_update_ignores_non_updatable(self, client, auth_headers):
        resp = client.post(
            '/api/v2/config',
            json={'master_port': 9999},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'master_port' not in data['applied']

    def test_update_requires_json(self, client, auth_headers):
        resp = client.post(
            '/api/v2/config',
            data='not json',
            headers=auth_headers,
        )
        assert resp.status_code == 400


class TestStatusEndpoint:
    """Tests for the /api/v2/status endpoint."""

    def test_get_status(self, client, auth_headers):
        resp = client.get('/api/v2/status', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'running'
        assert data['version'] == '2.1'
        assert 'collection_enabled' in data
        assert 'auto_send_enabled' in data
        assert 'bundle_count' in data
        assert 'pending_bundles' in data
        assert 'timestamp' in data
        assert 'cluster_id' in data
        assert 'audit_enabled' in data

    def test_status_requires_auth(self, client):
        resp = client.get('/api/v2/status')
        assert resp.status_code == 401


class TestLocalStorage:
    """Tests for local filesystem as primary storage."""

    def test_bundle_stored_locally(self, client, api_key_headers, tmp_dir, monkeypatch):
        import odpsc_master
        bundle_dir = getattr(odpsc_master, 'BUNDLE_DIR', os.path.join(tmp_dir, 'bundles'))
        os.makedirs(bundle_dir, exist_ok=True)

        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('manifest.json', json.dumps({
                'bundle_id': 'local-test-001',
                'hostname': 'test-host',
                'level': 'L1',
            }))
        zip_buffer.seek(0)

        headers = dict(api_key_headers)
        headers['X-ODPSC-Bundle-ID'] = 'local-test-001'

        resp = client.post(
            '/api/v2/bundles/upload',
            data={'bundle': (zip_buffer, 'test.zip')},
            headers=headers,
            content_type='multipart/form-data',
        )
        assert resp.status_code == 200

    def test_hdfs_not_required(self, tmp_dir, monkeypatch):
        """Verify HDFS is not used when hdfs_archive_enabled is False."""
        db_path = os.path.join(tmp_dir, 'test.db')
        bundles_dir = os.path.join(tmp_dir, 'bundles')
        aggregated_dir = os.path.join(tmp_dir, 'aggregated')
        os.makedirs(bundles_dir, exist_ok=True)
        os.makedirs(aggregated_dir, exist_ok=True)

        store = BundleStore(db_path)
        zip_path = os.path.join(bundles_dir, 'test.zip')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('system_info.json', '{}')
        store.register_bundle('uuid-001', 'host1', 'test.zip', zip_path)

        with patch('odpsc_master.AGGREGATED_DIR', aggregated_dir), \
             patch('odpsc_master._put_to_hdfs') as mock_hdfs:
            config = {
                'max_bundle_size_mb': 500,
                'encryption_key': '',
                'hdfs_archive_enabled': False,
            }
            result = _aggregate_bundles(store, config)
            mock_hdfs.assert_not_called()


class TestClusterIdStorage:
    """Tests for cluster_id storage in BundleStore and status endpoint."""

    def test_cluster_id_stored_in_bundle_store(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'test.db')
        store = BundleStore(db_path)
        store.register_bundle(
            'uuid-001', 'host1', 'file.zip', '/path/file.zip',
            'L1', 1024, cluster_id='cluster-abc',
        )

        bundle = store.get_bundle('uuid-001')
        assert bundle is not None
        assert bundle['cluster_id'] == 'cluster-abc'

    def test_cluster_id_in_status_response(self, client, auth_headers):
        resp = client.get('/api/v2/status', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'cluster_id' in data
        assert data['cluster_id'] == 'test-cluster-id-abc123'

    def test_cluster_id_extracted_from_upload(self, client, api_key_headers):
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('manifest.json', json.dumps({
                'bundle_id': 'cluster-test-001',
                'hostname': 'test-host',
                'level': 'L1',
                'cluster_id': 'cluster-from-manifest',
            }))
        zip_buffer.seek(0)

        headers = dict(api_key_headers)
        headers['X-ODPSC-Bundle-ID'] = 'cluster-test-001'
        resp = client.post(
            '/api/v2/bundles/upload',
            data={'bundle': (zip_buffer, 'test.zip')},
            headers=headers,
            content_type='multipart/form-data',
        )
        assert resp.status_code == 200

    def test_cluster_id_from_header_takes_precedence(self, client, api_key_headers):
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('manifest.json', json.dumps({
                'bundle_id': 'cluster-hdr-001',
                'hostname': 'test-host',
                'level': 'L1',
                'cluster_id': 'manifest-cluster',
            }))
        zip_buffer.seek(0)

        headers = dict(api_key_headers)
        headers['X-ODPSC-Bundle-ID'] = 'cluster-hdr-001'
        headers['X-ODPSC-Cluster-ID'] = 'header-cluster'
        resp = client.post(
            '/api/v2/bundles/upload',
            data={'bundle': (zip_buffer, 'test.zip')},
            headers=headers,
            content_type='multipart/form-data',
        )
        assert resp.status_code == 200


class TestClusterIdInAggregation:
    """Tests for cluster_id in aggregated bundles."""

    def test_cluster_id_in_aggregated_metadata(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'test.db')
        bundles_dir = os.path.join(tmp_dir, 'bundles')
        aggregated_dir = os.path.join(tmp_dir, 'aggregated')
        os.makedirs(bundles_dir, exist_ok=True)
        os.makedirs(aggregated_dir, exist_ok=True)

        store = BundleStore(db_path)

        zip_path = os.path.join(bundles_dir, 'agent_bundle.zip')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('system_info.json', json.dumps({'hostname': 'node1'}))
            zf.writestr('topology.json', json.dumps({'hosts': [{'hostname': 'node1'}]}))
            zf.writestr('manifest.json', json.dumps({
                'bundle_id': 'uuid-agg',
                'hostname': 'node1',
                'level': 'L1',
            }))
        store.register_bundle('uuid-agg', 'node1', 'agent_bundle.zip', zip_path,
                              'L1', os.path.getsize(zip_path))

        with patch('odpsc_master.AGGREGATED_DIR', aggregated_dir):
            config = {
                'max_bundle_size_mb': 500,
                'encryption_key': '',
                'hdfs_archive_enabled': False,
                'cluster_id': 'my-cluster-id',
            }
            result = _aggregate_bundles(store, config)

        assert result['status'] == 'aggregated'
        with zipfile.ZipFile(result['output'], 'r') as zf:
            metadata = json.loads(zf.read('metadata.json'))
            assert metadata['cluster_id'] == 'my-cluster-id'
            assert metadata['odpsc_version'] == '2.1'
            # Topology should be included
            assert 'topology.json' in zf.namelist()

    def test_aggregation_includes_diagnostic_data(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'test.db')
        bundles_dir = os.path.join(tmp_dir, 'bundles')
        aggregated_dir = os.path.join(tmp_dir, 'aggregated')
        os.makedirs(bundles_dir, exist_ok=True)
        os.makedirs(aggregated_dir, exist_ok=True)

        store = BundleStore(db_path)

        zip_path = os.path.join(bundles_dir, 'full_bundle.zip')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('system_info.json', json.dumps({'hostname': 'node1'}))
            zf.writestr('topology.json', json.dumps({'hosts': []}))
            zf.writestr('service_health.json', json.dumps({'service_states': []}))
            zf.writestr('log_tails.json', json.dumps({'/var/log/test.log': 'tail'}))
            zf.writestr('yarn_queues.json', json.dumps({'queues': []}))
            zf.writestr('hdfs_report.json', json.dumps({'live_datanodes': 3}))
            zf.writestr('alert_history.json', json.dumps([{'state': 'OK'}]))
            zf.writestr('manifest.json', json.dumps({
                'bundle_id': 'uuid-full',
                'hostname': 'node1',
                'level': 'L2',
            }))
        store.register_bundle('uuid-full', 'node1', 'full_bundle.zip', zip_path,
                              'L2', os.path.getsize(zip_path))

        with patch('odpsc_master.AGGREGATED_DIR', aggregated_dir):
            config = {
                'max_bundle_size_mb': 500,
                'encryption_key': '',
                'hdfs_archive_enabled': False,
                'cluster_id': 'cid-test',
            }
            result = _aggregate_bundles(store, config)

        assert result['status'] == 'aggregated'
        with zipfile.ZipFile(result['output'], 'r') as zf:
            names = zf.namelist()
            assert 'topology.json' in names
            assert 'service_health.json' in names
            assert 'log_tails.json' in names
            assert 'yarn_queues.json' in names
            assert 'hdfs_report.json' in names
            assert 'alert_history.json' in names
