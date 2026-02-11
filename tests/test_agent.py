"""
Tests for the ODPSC Agent v2 module.
"""

import json
import os
import shutil
import tempfile
import time
import uuid
import zipfile
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from odpsc_agent import (
    cleanup_sent,
    collect_configs,
    collect_logs,
    collect_metrics,
    collect_system_info,
    create_bundle,
    ensure_dirs,
    load_config,
    mask_sensitive_data,
    retry_pending,
    run_collection,
    upload_bundle,
)


class TestLoadConfig:
    """Tests for configuration loading."""

    def test_load_default_config(self, tmp_dir):
        config = load_config(os.path.join(tmp_dir, 'nonexistent.json'))
        assert config['collection_enabled'] is True
        assert 'master_url' in config
        assert 'api_key' in config
        assert 'bundle_level' in config

    def test_load_custom_config(self, agent_config):
        config, config_path = agent_config
        loaded = load_config(config_path)
        assert loaded['cluster_name'] == 'test-cluster'
        assert loaded['api_key'] == 'test-api-key-12345'

    def test_load_invalid_json(self, tmp_dir):
        config_path = os.path.join(tmp_dir, 'bad.json')
        with open(config_path, 'w') as f:
            f.write('not json{{{')
        config = load_config(config_path)
        assert config['collection_enabled'] is True


class TestCollectLogs:
    """Tests for log collection."""

    def test_collect_existing_logs(self, tmp_dir):
        log_file = os.path.join(tmp_dir, 'test.log')
        with open(log_file, 'w') as f:
            f.write('ERROR test error\nINFO test info\n')

        logs = collect_logs([os.path.join(tmp_dir, '*.log')])
        assert len(logs) == 1
        assert 'ERROR test error' in list(logs.values())[0]

    def test_collect_no_matching_files(self):
        logs = collect_logs(['/nonexistent/path/*.log'])
        assert len(logs) == 0

    def test_respects_max_size(self, tmp_dir):
        log_file = os.path.join(tmp_dir, 'big.log')
        with open(log_file, 'w') as f:
            f.write('x' * (2 * 1024 * 1024))

        logs = collect_logs([os.path.join(tmp_dir, '*.log')], max_size_mb=1)
        content = list(logs.values())[0]
        assert len(content) <= 1 * 1024 * 1024

    def test_skips_old_files(self, tmp_dir):
        log_file = os.path.join(tmp_dir, 'old.log')
        with open(log_file, 'w') as f:
            f.write('old data')
        old_time = os.path.getmtime(log_file) - (30 * 86400)
        os.utime(log_file, (old_time, old_time))

        logs = collect_logs([os.path.join(tmp_dir, '*.log')], retention_days=7)
        assert len(logs) == 0

    def test_skips_directories(self, tmp_dir):
        os.makedirs(os.path.join(tmp_dir, 'subdir.log'), exist_ok=True)
        logs = collect_logs([os.path.join(tmp_dir, '*.log')])
        assert len(logs) == 0

    def test_collects_multiple_patterns(self, tmp_dir):
        for name in ('hadoop.log', 'yarn.log', 'hive.log'):
            with open(os.path.join(tmp_dir, name), 'w') as f:
                f.write(f'content of {name}')

        logs = collect_logs([os.path.join(tmp_dir, '*.log')])
        assert len(logs) == 3


class TestCollectMetrics:
    """Tests for metric collection."""

    def test_collect_system_metrics(self):
        metrics = collect_metrics()
        assert 'timestamp' in metrics
        assert 'hostname' in metrics
        assert 'system' in metrics
        assert 'cpu_percent' in metrics['system']
        assert 'memory' in metrics['system']
        assert 'disk_usage' in metrics['system']

    @patch('odpsc_agent.requests.get')
    def test_collect_with_ambari(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'metrics': 'data'}
        mock_get.return_value = mock_resp

        metrics = collect_metrics(
            ambari_server_url='http://ambari:8080',
            cluster_name='test',
        )
        assert 'ambari' in metrics

    @patch('odpsc_agent.requests.get')
    def test_collect_ambari_failure(self, mock_get):
        import requests as req
        mock_get.side_effect = req.RequestException("connection failed")
        metrics = collect_metrics(
            ambari_server_url='http://ambari:8080',
            cluster_name='test',
        )
        assert 'system' in metrics
        assert 'ambari' not in metrics


class TestCollectConfigs:
    """Tests for configuration file collection."""

    def test_collect_configs(self, tmp_dir):
        config_file = os.path.join(tmp_dir, 'core-site.xml')
        with open(config_file, 'w') as f:
            f.write(
                '<configuration>\n'
                '  <property>\n'
                '    <name>fs.defaultFS</name>\n'
                '    <value>hdfs://namenode:8020</value>\n'
                '  </property>\n'
                '</configuration>\n'
            )

        configs = collect_configs([os.path.join(tmp_dir, '*.xml')])
        assert len(configs) == 1
        content = list(configs.values())[0]
        assert 'fs.defaultFS' in content

    def test_masks_passwords(self, tmp_dir):
        config_file = os.path.join(tmp_dir, 'hdfs-site.xml')
        with open(config_file, 'w') as f:
            f.write(
                '<configuration>\n'
                '  <property>\n'
                '    <name>dfs.namenode.password</name>\n'
                '    <value>secret123</value>\n'
                '  </property>\n'
                '</configuration>\n'
            )

        configs = collect_configs([os.path.join(tmp_dir, '*.xml')])
        content = list(configs.values())[0]
        assert 'secret123' not in content
        assert '****MASKED****' in content

    def test_no_matching_configs(self):
        configs = collect_configs(['/nonexistent/*.xml'])
        assert len(configs) == 0


class TestCollectSystemInfo:
    """Tests for system info collection."""

    def test_collect_system_info(self):
        info = collect_system_info()
        assert 'hostname' in info
        assert 'os' in info
        assert 'python_version' in info
        assert 'java_version' in info
        assert 'timestamp' in info
        assert 'ip_address' in info


class TestEnhancedMasking:
    """Tests for enhanced Hadoop-specific sensitive data masking."""

    def test_masks_jdbc_passwords(self):
        content = 'jdbc:mysql://host:3306/db?password=mySecret123&user=admin'
        masked = mask_sensitive_data(content)
        assert 'mySecret123' not in masked
        assert '****MASKED****' in masked

    def test_masks_s3_keys(self):
        content = '<name>fs.s3a.secret.key</name>\n<value>MYSECRETKEY123</value>'
        masked = mask_sensitive_data(content)
        assert 'MYSECRETKEY123' not in masked

    def test_masks_azure_keys(self):
        content = 'fs.azure.account.key.storage=ABCsecretKey123'
        masked = mask_sensitive_data(content)
        assert 'ABCsecretKey123' not in masked

    def test_masks_ldap_passwords(self):
        content = 'bind_password = ldapsecret123'
        masked = mask_sensitive_data(content)
        assert 'ldapsecret123' not in masked

    def test_masks_keystore_passwords(self):
        content = 'keystore_password = keystorepass123'
        masked = mask_sensitive_data(content)
        assert 'keystorepass123' not in masked

    def test_masks_truststore_passwords(self):
        content = 'truststore_password = truststorepass123'
        masked = mask_sensitive_data(content)
        assert 'truststorepass123' not in masked

    def test_masks_kerberos_keytabs(self):
        content = 'keytab = /etc/security/keytabs/nn.service.keytab'
        masked = mask_sensitive_data(content)
        assert '/etc/security/keytabs/nn.service.keytab' not in masked


class TestBundleLevels:
    """Tests for L1/L2/L3 bundle level collection."""

    def test_l1_contains_configs_and_sysinfo(self, tmp_dir):
        data = {
            'configs': {'/etc/hadoop/conf/core-site.xml': '<config/>'},
            'system_info': {'hostname': 'testhost'},
            'metrics': {'cpu_percent': 50.0},
            'logs': {'/var/log/test.log': 'ERROR test'},
        }
        bundle_id = str(uuid.uuid4())
        zip_path = create_bundle(data, bundle_id, 'L1', tmp_dir)

        with zipfile.ZipFile(zip_path, 'r') as zf:
            names = zf.namelist()
            assert 'manifest.json' in names
            assert 'system_info.json' in names
            assert any('configs/' in n for n in names)
            assert 'metrics.json' not in names
            assert not any('logs/' in n for n in names)

    def test_l2_contains_metrics(self, tmp_dir):
        data = {
            'configs': {'/etc/hadoop/conf/core-site.xml': '<config/>'},
            'system_info': {'hostname': 'testhost'},
            'metrics': {'cpu_percent': 50.0},
            'logs': {'/var/log/test.log': 'ERROR test'},
        }
        bundle_id = str(uuid.uuid4())
        zip_path = create_bundle(data, bundle_id, 'L2', tmp_dir)

        with zipfile.ZipFile(zip_path, 'r') as zf:
            names = zf.namelist()
            assert 'metrics.json' in names
            assert 'system_info.json' in names
            assert any('configs/' in n for n in names)
            assert not any('logs/' in n for n in names)

    def test_l3_contains_everything(self, tmp_dir):
        data = {
            'configs': {'/etc/hadoop/conf/core-site.xml': '<config/>'},
            'system_info': {'hostname': 'testhost'},
            'metrics': {'cpu_percent': 50.0},
            'logs': {'/var/log/test.log': 'ERROR test'},
        }
        bundle_id = str(uuid.uuid4())
        zip_path = create_bundle(data, bundle_id, 'L3', tmp_dir)

        with zipfile.ZipFile(zip_path, 'r') as zf:
            names = zf.namelist()
            assert 'metrics.json' in names
            assert 'system_info.json' in names
            assert any('configs/' in n for n in names)
            assert any('logs/' in n for n in names)


class TestBundleManifest:
    """Tests for bundle manifest generation."""

    def test_manifest_contains_uuid(self, tmp_dir):
        data = {
            'configs': {},
            'system_info': {'hostname': 'testhost'},
        }
        bundle_id = str(uuid.uuid4())
        zip_path = create_bundle(data, bundle_id, 'L1', tmp_dir)

        with zipfile.ZipFile(zip_path, 'r') as zf:
            manifest = json.loads(zf.read('manifest.json'))
            assert manifest['bundle_id'] == bundle_id
            assert manifest['level'] == 'L1'
            assert manifest['odpsc_version'] == '2.0'
            assert 'hostname' in manifest
            assert 'timestamp' in manifest

    def test_manifest_lists_contents(self, tmp_dir):
        data = {
            'configs': {'/etc/test.xml': '<config/>'},
            'system_info': {'hostname': 'testhost'},
            'metrics': {'cpu': 50},
        }
        bundle_id = str(uuid.uuid4())
        zip_path = create_bundle(data, bundle_id, 'L2', tmp_dir)

        with zipfile.ZipFile(zip_path, 'r') as zf:
            manifest = json.loads(zf.read('manifest.json'))
            assert 'system_info.json' in manifest['contents']
            assert 'metrics.json' in manifest['contents']


class TestLocalStaging:
    """Tests for outbox/sent/failed directory lifecycle."""

    def test_ensure_dirs_creates_directories(self, tmp_dir, monkeypatch):
        monkeypatch.setattr('odpsc_agent.OUTBOX_DIR', os.path.join(tmp_dir, 'outbox'))
        monkeypatch.setattr('odpsc_agent.SENT_DIR', os.path.join(tmp_dir, 'sent'))
        monkeypatch.setattr('odpsc_agent.FAILED_DIR', os.path.join(tmp_dir, 'failed'))
        ensure_dirs()
        assert os.path.isdir(os.path.join(tmp_dir, 'outbox'))
        assert os.path.isdir(os.path.join(tmp_dir, 'sent'))
        assert os.path.isdir(os.path.join(tmp_dir, 'failed'))

    @patch('odpsc_agent.upload_bundle')
    def test_collection_stages_to_outbox_on_failure(self, mock_upload, tmp_dir, monkeypatch):
        mock_upload.return_value = (False, 'connection_error')
        monkeypatch.setattr('odpsc_agent.OUTBOX_DIR', os.path.join(tmp_dir, 'outbox'))
        monkeypatch.setattr('odpsc_agent.SENT_DIR', os.path.join(tmp_dir, 'sent'))
        monkeypatch.setattr('odpsc_agent.FAILED_DIR', os.path.join(tmp_dir, 'failed'))
        monkeypatch.setattr('odpsc_agent.RETRY_STATE_FILE',
                            os.path.join(tmp_dir, 'retry_state.json'))

        config = {
            'collection_enabled': True,
            'master_url': 'http://localhost:8085',
            'api_key': 'test-key',
            'bundle_level': 'L1',
            'config_paths': [],
        }
        result = run_collection(config, level='L1')
        assert result is not None
        # File should be in outbox
        outbox_files = os.listdir(os.path.join(tmp_dir, 'outbox'))
        assert len(outbox_files) == 1

    @patch('odpsc_agent.upload_bundle')
    def test_collection_moves_to_sent_on_success(self, mock_upload, tmp_dir, monkeypatch):
        mock_upload.return_value = (True, 'received')
        monkeypatch.setattr('odpsc_agent.OUTBOX_DIR', os.path.join(tmp_dir, 'outbox'))
        monkeypatch.setattr('odpsc_agent.SENT_DIR', os.path.join(tmp_dir, 'sent'))
        monkeypatch.setattr('odpsc_agent.FAILED_DIR', os.path.join(tmp_dir, 'failed'))
        monkeypatch.setattr('odpsc_agent.RETRY_STATE_FILE',
                            os.path.join(tmp_dir, 'retry_state.json'))

        config = {
            'collection_enabled': True,
            'master_url': 'http://localhost:8085',
            'api_key': 'test-key',
            'bundle_level': 'L1',
            'config_paths': [],
        }
        result = run_collection(config, level='L1')
        assert result is not None
        # File should be in sent, not outbox
        sent_files = os.listdir(os.path.join(tmp_dir, 'sent'))
        assert len(sent_files) == 1
        outbox_files = os.listdir(os.path.join(tmp_dir, 'outbox'))
        assert len(outbox_files) == 0


class TestRetryMechanism:
    """Tests for exponential backoff retry mechanism."""

    @patch('odpsc_agent.upload_bundle')
    def test_retry_uploads_pending(self, mock_upload, tmp_dir, monkeypatch):
        mock_upload.return_value = (True, 'received')
        outbox = os.path.join(tmp_dir, 'outbox')
        sent = os.path.join(tmp_dir, 'sent')
        failed = os.path.join(tmp_dir, 'failed')
        monkeypatch.setattr('odpsc_agent.OUTBOX_DIR', outbox)
        monkeypatch.setattr('odpsc_agent.SENT_DIR', sent)
        monkeypatch.setattr('odpsc_agent.FAILED_DIR', failed)
        monkeypatch.setattr('odpsc_agent.RETRY_STATE_FILE',
                            os.path.join(tmp_dir, 'retry_state.json'))

        # Create a pending bundle in outbox
        os.makedirs(outbox, exist_ok=True)
        os.makedirs(sent, exist_ok=True)
        os.makedirs(failed, exist_ok=True)

        zip_path = os.path.join(outbox, 'test_bundle.zip')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('data.json', '{}')

        config = {'master_url': 'http://localhost:8085', 'api_key': 'test-key'}
        retry_pending(config)

        assert not os.path.exists(zip_path)
        assert len(os.listdir(sent)) == 1

    @patch('odpsc_agent.upload_bundle')
    def test_retry_moves_to_failed_after_max_attempts(self, mock_upload, tmp_dir, monkeypatch):
        mock_upload.return_value = (False, 'connection_error')
        outbox = os.path.join(tmp_dir, 'outbox')
        sent = os.path.join(tmp_dir, 'sent')
        failed = os.path.join(tmp_dir, 'failed')
        monkeypatch.setattr('odpsc_agent.OUTBOX_DIR', outbox)
        monkeypatch.setattr('odpsc_agent.SENT_DIR', sent)
        monkeypatch.setattr('odpsc_agent.FAILED_DIR', failed)
        state_file = os.path.join(tmp_dir, 'retry_state.json')
        monkeypatch.setattr('odpsc_agent.RETRY_STATE_FILE', state_file)
        monkeypatch.setattr('odpsc_agent.MAX_RETRY_ATTEMPTS', 3)

        os.makedirs(outbox, exist_ok=True)
        os.makedirs(sent, exist_ok=True)
        os.makedirs(failed, exist_ok=True)

        zip_path = os.path.join(outbox, 'test_bundle.zip')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('data.json', '{}')

        # Pre-populate retry state with max attempts reached
        state = {
            'test_bundle.zip': {
                'bundle_id': 'test-id',
                'attempts': 3,
                'last_attempt': time.time() - 1000,
            }
        }
        with open(state_file, 'w') as f:
            json.dump(state, f)

        config = {'master_url': 'http://localhost:8085', 'api_key': 'test-key'}
        retry_pending(config)

        assert not os.path.exists(zip_path)
        assert len(os.listdir(failed)) == 1
        assert len(os.listdir(sent)) == 0

    @patch('odpsc_agent.upload_bundle')
    def test_retry_state_persistence(self, mock_upload, tmp_dir, monkeypatch):
        mock_upload.return_value = (False, 'connection_error')
        outbox = os.path.join(tmp_dir, 'outbox')
        sent = os.path.join(tmp_dir, 'sent')
        failed = os.path.join(tmp_dir, 'failed')
        monkeypatch.setattr('odpsc_agent.OUTBOX_DIR', outbox)
        monkeypatch.setattr('odpsc_agent.SENT_DIR', sent)
        monkeypatch.setattr('odpsc_agent.FAILED_DIR', failed)
        state_file = os.path.join(tmp_dir, 'retry_state.json')
        monkeypatch.setattr('odpsc_agent.RETRY_STATE_FILE', state_file)

        os.makedirs(outbox, exist_ok=True)
        os.makedirs(sent, exist_ok=True)
        os.makedirs(failed, exist_ok=True)

        zip_path = os.path.join(outbox, 'test_bundle.zip')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('data.json', '{}')

        config = {'master_url': 'http://localhost:8085', 'api_key': 'test-key'}
        retry_pending(config)

        # State should be persisted
        assert os.path.exists(state_file)
        with open(state_file, 'r') as f:
            state = json.load(f)
        assert 'test_bundle.zip' in state
        assert state['test_bundle.zip']['attempts'] == 1

    def test_retry_respects_backoff_delay(self, tmp_dir, monkeypatch):
        outbox = os.path.join(tmp_dir, 'outbox')
        sent = os.path.join(tmp_dir, 'sent')
        failed = os.path.join(tmp_dir, 'failed')
        monkeypatch.setattr('odpsc_agent.OUTBOX_DIR', outbox)
        monkeypatch.setattr('odpsc_agent.SENT_DIR', sent)
        monkeypatch.setattr('odpsc_agent.FAILED_DIR', failed)
        state_file = os.path.join(tmp_dir, 'retry_state.json')
        monkeypatch.setattr('odpsc_agent.RETRY_STATE_FILE', state_file)

        os.makedirs(outbox, exist_ok=True)
        os.makedirs(sent, exist_ok=True)
        os.makedirs(failed, exist_ok=True)

        zip_path = os.path.join(outbox, 'test_bundle.zip')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('data.json', '{}')

        # Pre-populate state with very recent attempt
        state = {
            'test_bundle.zip': {
                'bundle_id': 'test-id',
                'attempts': 1,
                'last_attempt': time.time(),  # Just now
            }
        }
        with open(state_file, 'w') as f:
            json.dump(state, f)

        with patch('odpsc_agent.upload_bundle') as mock_upload:
            config = {'master_url': 'http://localhost:8085', 'api_key': 'test-key'}
            retry_pending(config)
            # Should skip due to backoff
            mock_upload.assert_not_called()


class TestApiKeyAuth:
    """Tests for API key upload authentication."""

    @patch('odpsc_agent.requests.post')
    def test_upload_with_valid_key(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'status': 'received'}
        mock_post.return_value = mock_resp

        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as f:
            with zipfile.ZipFile(f, 'w') as zf:
                zf.writestr('data.json', '{}')
            zip_path = f.name

        try:
            success, status = upload_bundle(zip_path, 'http://master:8085', 'my-key', 'bundle-001')
            assert success is True
            assert status == 'received'

            # Verify headers were sent
            call_args = mock_post.call_args
            headers = call_args[1].get('headers', {})
            assert headers['Authorization'] == 'Bearer my-key'
            assert headers['X-ODPSC-Bundle-ID'] == 'bundle-001'
        finally:
            os.unlink(zip_path)

    @patch('odpsc_agent.requests.post')
    def test_upload_auth_failure(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = 'Unauthorized'
        mock_post.return_value = mock_resp

        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as f:
            with zipfile.ZipFile(f, 'w') as zf:
                zf.writestr('data.json', '{}')
            zip_path = f.name

        try:
            success, status = upload_bundle(zip_path, 'http://master:8085', 'bad-key', 'bundle-001')
            assert success is False
            assert status == 'auth_failed'
        finally:
            os.unlink(zip_path)

    @patch('odpsc_agent.requests.post')
    def test_upload_rate_limited(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = 'Too many requests'
        mock_post.return_value = mock_resp

        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as f:
            with zipfile.ZipFile(f, 'w') as zf:
                zf.writestr('data.json', '{}')
            zip_path = f.name

        try:
            success, status = upload_bundle(zip_path, 'http://master:8085', 'key', 'bundle-001')
            assert success is False
            assert status == 'rate_limited'
        finally:
            os.unlink(zip_path)

    @patch('odpsc_agent.requests.post')
    def test_upload_connection_error(self, mock_post):
        import requests as req
        mock_post.side_effect = req.RequestException("connection failed")

        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as f:
            with zipfile.ZipFile(f, 'w') as zf:
                zf.writestr('data.json', '{}')
            zip_path = f.name

        try:
            success, status = upload_bundle(zip_path, 'http://master:8085', 'key', 'bundle-001')
            assert success is False
            assert status == 'connection_error'
        finally:
            os.unlink(zip_path)


class TestSentCleanup:
    """Tests for sent bundle cleanup."""

    def test_cleanup_old_sent_bundles(self, tmp_dir, monkeypatch):
        sent = os.path.join(tmp_dir, 'sent')
        os.makedirs(sent, exist_ok=True)
        monkeypatch.setattr('odpsc_agent.SENT_DIR', sent)
        monkeypatch.setattr('odpsc_agent.OUTBOX_DIR', os.path.join(tmp_dir, 'outbox'))
        monkeypatch.setattr('odpsc_agent.FAILED_DIR', os.path.join(tmp_dir, 'failed'))

        # Create an old file
        old_file = os.path.join(sent, 'old_bundle.zip')
        with open(old_file, 'w') as f:
            f.write('old')
        old_time = time.time() - (10 * 86400)
        os.utime(old_file, (old_time, old_time))

        # Create a recent file
        new_file = os.path.join(sent, 'new_bundle.zip')
        with open(new_file, 'w') as f:
            f.write('new')

        cleanup_sent(max_age_days=7)

        assert not os.path.exists(old_file)
        assert os.path.exists(new_file)


class TestCreateBundle:
    """Tests for bundle creation."""

    def test_creates_valid_zip(self, tmp_dir):
        data = {
            'logs': {'/var/log/test.log': 'ERROR test'},
            'metrics': {'cpu_percent': 50.0},
            'configs': {'/etc/hadoop/core-site.xml': '<config/>'},
            'system_info': {'hostname': 'testhost'},
        }
        bundle_id = str(uuid.uuid4())
        zip_path = create_bundle(data, bundle_id, 'L3', tmp_dir)
        assert os.path.exists(zip_path)
        assert zip_path.endswith('.zip')

        with zipfile.ZipFile(zip_path, 'r') as zf:
            names = zf.namelist()
            assert any('logs/' in n for n in names)
            assert 'metrics.json' in names
            assert any('configs/' in n for n in names)
            assert 'system_info.json' in names
            assert 'manifest.json' in names

    def test_empty_data_bundle(self, tmp_dir):
        data = {'logs': {}, 'metrics': {}, 'configs': {}, 'system_info': {}}
        bundle_id = str(uuid.uuid4())
        zip_path = create_bundle(data, bundle_id, 'L1', tmp_dir)
        assert os.path.exists(zip_path)

        with zipfile.ZipFile(zip_path, 'r') as zf:
            assert 'manifest.json' in zf.namelist()
            assert 'system_info.json' in zf.namelist()


class TestRunCollection:
    """Tests for the run_collection function."""

    def test_collection_disabled(self, tmp_dir, monkeypatch):
        monkeypatch.setattr('odpsc_agent.OUTBOX_DIR', os.path.join(tmp_dir, 'outbox'))
        monkeypatch.setattr('odpsc_agent.SENT_DIR', os.path.join(tmp_dir, 'sent'))
        monkeypatch.setattr('odpsc_agent.FAILED_DIR', os.path.join(tmp_dir, 'failed'))

        config = {'collection_enabled': False}
        result = run_collection(config)
        assert result is None

    def test_invalid_bundle_level(self, tmp_dir, monkeypatch):
        monkeypatch.setattr('odpsc_agent.OUTBOX_DIR', os.path.join(tmp_dir, 'outbox'))
        monkeypatch.setattr('odpsc_agent.SENT_DIR', os.path.join(tmp_dir, 'sent'))
        monkeypatch.setattr('odpsc_agent.FAILED_DIR', os.path.join(tmp_dir, 'failed'))

        config = {'collection_enabled': True, 'bundle_level': 'L1'}
        result = run_collection(config, level='L4')
        assert result is None
