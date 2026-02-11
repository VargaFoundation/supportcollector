"""
Tests for the ODPSC Master module.
"""

import base64
import json
import os
import zipfile
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from odpsc_master import (
    _aggregate_data,
    _create_master_bundle,
    _encrypt_bundle,
    create_app,
    load_config,
)


class TestLoadConfig:
    """Tests for master configuration loading."""

    def test_load_defaults(self, tmp_dir):
        config = load_config(os.path.join(tmp_dir, 'nonexistent.json'))
        assert config['collection_enabled'] is True
        assert config['auto_send_enabled'] is True
        assert config['master_port'] == 8085

    def test_load_custom(self, master_config):
        config, config_path = master_config
        loaded = load_config(config_path)
        assert loaded['cluster_name'] == 'test-cluster'


class TestSubmitDataEndpoint:
    """Tests for the /api/v1/submit_data endpoint."""

    def test_submit_valid_bundle(self, client, tmp_dir):
        # Create a test zip bundle
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('data.json', '{"test": true}')
        zip_buffer.seek(0)

        resp = client.post(
            '/api/v1/submit_data',
            data={'bundle': (zip_buffer, 'test_agent.zip')},
            content_type='multipart/form-data',
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'received'

    def test_submit_no_bundle(self, client):
        resp = client.post('/api/v1/submit_data')
        assert resp.status_code == 400

    def test_submit_empty_filename(self, client):
        resp = client.post(
            '/api/v1/submit_data',
            data={'bundle': (BytesIO(b''), '')},
            content_type='multipart/form-data',
        )
        assert resp.status_code == 400


class TestCollectEndpoint:
    """Tests for the /api/v1/collect endpoint."""

    @patch('odpsc_master._trigger_agent_collection')
    @patch('odpsc_master._put_to_hdfs')
    def test_manual_collect(self, mock_hdfs, mock_trigger, client, auth_headers):
        mock_hdfs.return_value = '/odpsc/diagnostics/bundle.zip'
        resp = client.post(
            '/api/v1/collect',
            json={'send': False},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'done'

    def test_collect_requires_auth(self, client):
        resp = client.post('/api/v1/collect', json={'send': False})
        assert resp.status_code == 401

    def test_collect_wrong_auth(self, client):
        bad_auth = base64.b64encode(b'wrong:wrong').decode('utf-8')
        resp = client.post(
            '/api/v1/collect',
            json={'send': False},
            headers={'Authorization': f'Basic {bad_auth}'},
        )
        assert resp.status_code == 401

    @patch('odpsc_master._trigger_agent_collection')
    @patch('odpsc_master._put_to_hdfs')
    def test_collect_disabled(self, mock_hdfs, mock_trigger, master_config):
        config, _ = master_config
        config['collection_enabled'] = False
        app = create_app(config)
        app.config['TESTING'] = True
        client = app.test_client()

        credentials = base64.b64encode(b'admin:admin').decode('utf-8')
        resp = client.post(
            '/api/v1/collect',
            json={'send': False},
            headers={'Authorization': f'Basic {credentials}'},
        )
        assert resp.status_code == 403


class TestConfigEndpoints:
    """Tests for the /api/v1/config endpoints."""

    def test_get_config(self, client, auth_headers):
        resp = client.get('/api/v1/config', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'collection_enabled' in data
        # Sensitive fields should be masked
        assert data.get('support_token') in ('****MASKED****', '')

    def test_get_config_requires_auth(self, client):
        resp = client.get('/api/v1/config')
        assert resp.status_code == 401

    def test_update_config(self, client, auth_headers, tmp_dir, monkeypatch):
        # Redirect config writes to a writable temp path
        config_path = os.path.join(tmp_dir, 'master_config.json')
        monkeypatch.setattr('odpsc_master.CONFIG_PATH', config_path)

        resp = client.post(
            '/api/v1/config',
            json={'collection_enabled': False},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'updated'
        assert 'collection_enabled' in data['applied']

    def test_update_config_requires_auth(self, client):
        resp = client.post(
            '/api/v1/config',
            json={'collection_enabled': False},
        )
        assert resp.status_code == 401

    def test_update_ignores_non_updatable(self, client, auth_headers):
        resp = client.post(
            '/api/v1/config',
            json={'master_port': 9999},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        # master_port is not in the updatable whitelist
        assert 'master_port' not in data['applied']

    def test_update_requires_json(self, client, auth_headers):
        resp = client.post(
            '/api/v1/config',
            data='not json',
            headers=auth_headers,
        )
        assert resp.status_code == 400


class TestStatusEndpoint:
    """Tests for the /api/v1/status endpoint."""

    def test_get_status(self, client, auth_headers):
        resp = client.get('/api/v1/status', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'running'
        assert 'collection_enabled' in data
        assert 'auto_send_enabled' in data
        assert 'timestamp' in data

    def test_status_requires_auth(self, client):
        resp = client.get('/api/v1/status')
        assert resp.status_code == 401


class TestAggregateData:
    """Tests for data aggregation."""

    def test_aggregate_empty_dir(self, tmp_dir, monkeypatch):
        monkeypatch.setattr('odpsc_master.DATA_DIR', tmp_dir)
        result = _aggregate_data()
        assert result['agent_count'] == 0
        assert result['logs'] == {}

    def test_aggregate_agent_bundles(self, tmp_dir, monkeypatch):
        monkeypatch.setattr('odpsc_master.DATA_DIR', tmp_dir)

        # Create a fake agent bundle
        zip_path = os.path.join(tmp_dir, 'agent_test.zip')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('logs/test.log', 'ERROR test error')
            zf.writestr('metrics.json', '{"cpu_percent": 50}')
            zf.writestr('configs/core-site.xml', '<config/>')
            zf.writestr('system_info.json', '{"hostname": "node1"}')

        result = _aggregate_data()
        assert result['agent_count'] == 1
        assert len(result['logs']) == 1
        assert len(result['metrics']) == 1
        assert len(result['configs']) == 1
        assert len(result['system_info']) == 1


class TestCreateMasterBundle:
    """Tests for master bundle creation."""

    def test_creates_bundle(self, tmp_dir, monkeypatch):
        monkeypatch.setattr('odpsc_master.BUNDLE_DIR', tmp_dir)

        aggregated = {
            'logs': {'test.log': 'ERROR test'},
            'metrics': [{'cpu': 50}],
            'configs': {'core-site.xml': '<config/>'},
            'system_info': [{'hostname': 'node1'}],
            'analysis': {'error_summary': {}},
            'analysis_report': 'TEST REPORT',
            'agent_count': 1,
        }
        config = {'encryption_key': ''}

        zip_path = _create_master_bundle(aggregated, config)
        assert os.path.exists(zip_path)

        with zipfile.ZipFile(zip_path, 'r') as zf:
            names = zf.namelist()
            assert 'metrics.json' in names
            assert 'analysis.json' in names
            assert 'analysis_report.txt' in names
            assert 'metadata.json' in names


class TestEncryption:
    """Tests for bundle encryption."""

    def test_encrypt_and_verify(self, tmp_dir):
        # Create a test file
        test_file = os.path.join(tmp_dir, 'test.zip')
        with open(test_file, 'wb') as f:
            f.write(b'test data for encryption')

        encrypted_path = _encrypt_bundle(test_file, 'my-secret-key')
        assert encrypted_path.endswith('.enc')
        assert os.path.exists(encrypted_path)
        # Original should be removed
        assert not os.path.exists(test_file)

        # Verify we can decrypt
        import hashlib
        from cryptography.fernet import Fernet
        derived = base64.urlsafe_b64encode(
            hashlib.sha256(b'my-secret-key').digest()
        )
        fernet = Fernet(derived)
        with open(encrypted_path, 'rb') as f:
            decrypted = fernet.decrypt(f.read())
        assert decrypted == b'test data for encryption'

    def test_no_encryption_without_key(self, tmp_dir, monkeypatch):
        monkeypatch.setattr('odpsc_master.BUNDLE_DIR', tmp_dir)

        aggregated = {
            'logs': {},
            'metrics': [],
            'configs': {},
            'system_info': [],
            'agent_count': 0,
        }
        config = {'encryption_key': ''}

        zip_path = _create_master_bundle(aggregated, config)
        assert zip_path.endswith('.zip')
        assert not zip_path.endswith('.enc')
