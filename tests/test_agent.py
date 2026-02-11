"""
Tests for the ODPSC Agent module.
"""

import json
import os
import tempfile
import zipfile
from unittest.mock import MagicMock, patch

import pytest

from odpsc_agent import (
    collect_configs,
    collect_logs,
    collect_metrics,
    collect_system_info,
    create_bundle,
    load_config,
)


class TestLoadConfig:
    """Tests for configuration loading."""

    def test_load_default_config(self, tmp_dir):
        config = load_config(os.path.join(tmp_dir, 'nonexistent.json'))
        assert config['collection_enabled'] is True
        assert 'master_url' in config

    def test_load_custom_config(self, agent_config):
        config, config_path = agent_config
        loaded = load_config(config_path)
        assert loaded['cluster_name'] == 'test-cluster'

    def test_load_invalid_json(self, tmp_dir):
        config_path = os.path.join(tmp_dir, 'bad.json')
        with open(config_path, 'w') as f:
            f.write('not json{{{')
        config = load_config(config_path)
        # Should fall back to defaults
        assert config['collection_enabled'] is True


class TestCollectLogs:
    """Tests for log collection."""

    def test_collect_existing_logs(self, tmp_dir):
        # Create sample log files
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
        # Write 2MB of data
        with open(log_file, 'w') as f:
            f.write('x' * (2 * 1024 * 1024))

        logs = collect_logs([os.path.join(tmp_dir, '*.log')], max_size_mb=1)
        content = list(logs.values())[0]
        assert len(content) <= 1 * 1024 * 1024

    def test_skips_old_files(self, tmp_dir):
        log_file = os.path.join(tmp_dir, 'old.log')
        with open(log_file, 'w') as f:
            f.write('old data')
        # Set modification time to 30 days ago
        old_time = os.path.getmtime(log_file) - (30 * 86400)
        os.utime(log_file, (old_time, old_time))

        logs = collect_logs([os.path.join(tmp_dir, '*.log')], retention_days=7)
        assert len(logs) == 0

    def test_skips_directories(self, tmp_dir):
        os.makedirs(os.path.join(tmp_dir, 'subdir.log'), exist_ok=True)
        logs = collect_logs([os.path.join(tmp_dir, '*.log')])
        assert len(logs) == 0


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
        # Should still return system metrics without ambari
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


class TestCreateBundle:
    """Tests for bundle creation."""

    def test_creates_valid_zip(self, tmp_dir):
        data = {
            'logs': {'/var/log/test.log': 'ERROR test'},
            'metrics': {'cpu_percent': 50.0},
            'configs': {'/etc/hadoop/core-site.xml': '<config/>'},
            'system_info': {'hostname': 'testhost'},
        }
        zip_path = create_bundle(data, temp_dir=tmp_dir)
        assert os.path.exists(zip_path)
        assert zip_path.endswith('.zip')

        with zipfile.ZipFile(zip_path, 'r') as zf:
            names = zf.namelist()
            assert any('logs/' in n for n in names)
            assert 'metrics.json' in names
            assert any('configs/' in n for n in names)
            assert 'system_info.json' in names

    def test_empty_data_bundle(self, tmp_dir):
        data = {'logs': {}, 'metrics': {}, 'configs': {}, 'system_info': {}}
        zip_path = create_bundle(data, temp_dir=tmp_dir)
        assert os.path.exists(zip_path)

        with zipfile.ZipFile(zip_path, 'r') as zf:
            assert 'metrics.json' in zf.namelist()
