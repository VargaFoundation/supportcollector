"""
Shared test fixtures for ODPSC v2 tests.
"""

import json
import os
import sys
import tempfile

import pytest

# Add resources directory to path so we can import the modules directly
RESOURCES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'odpsc-mpack', 'services', 'ODPSC', 'resources',
)
sys.path.insert(0, RESOURCES_DIR)


@pytest.fixture
def tmp_dir():
    """Provide a temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory(prefix='odpsc_test_') as d:
        yield d


@pytest.fixture
def sample_logs():
    """Provide sample Hadoop log content for testing."""
    return {
        '/var/log/hadoop/hdfs-namenode.log': (
            "2025-01-15 10:00:00 INFO NameNode: Starting\n"
            "2025-01-15 10:00:01 INFO NameNode: Initialized\n"
            "2025-01-15 10:05:00 ERROR NameNode: Failed to connect to DataNode dn01\n"
            "2025-01-15 10:05:01 ERROR NameNode: java.net.ConnectException: Connection refused\n"
            "\tat sun.nio.ch.Net.connect0(Native Method)\n"
            "\tat sun.nio.ch.Net.connect(Net.java:474)\n"
            "2025-01-15 10:10:00 INFO NameNode: DataNode dn01 reconnected\n"
            "2025-01-15 11:00:00 ERROR NameNode: OutOfMemoryError: Java heap space\n"
            "2025-01-15 11:00:01 FATAL NameNode: Shutting down\n"
        ),
        '/var/log/yarn/resourcemanager.log': (
            "2025-01-15 09:00:00 INFO ResourceManager: Starting\n"
            "2025-01-15 09:00:01 INFO ResourceManager: Ready\n"
            "2025-01-15 09:30:00 ERROR ResourceManager: NodeUnhealthy: node02\n"
            "2025-01-15 09:30:01 ERROR ResourceManager: Exception in monitor\n"
            "java.lang.RuntimeException: Node unhealthy\n"
            "\tat org.apache.hadoop.yarn.server.resourcemanager.Monitor.run(Monitor.java:100)\n"
        ),
    }


@pytest.fixture
def hdfs_logs():
    """Provide HDFS-specific log content."""
    return {
        '/var/log/hadoop/hdfs-namenode.log': (
            "2025-01-15 10:00:00 ERROR BlockMissingException: Could not find block blk_123\n"
            "2025-01-15 10:01:00 ERROR NameNode: corrupt block blk_456 on datanode dn03\n"
            "2025-01-15 10:02:00 WARN NameNode: under-replication: blk_789 expected=3 live=1\n"
            "2025-01-15 10:03:00 ERROR Lease lease_001 on file /user/data.txt has expired\n"
            "2025-01-15 10:04:00 WARN NameNode: SafeMode is ON\n"
        ),
    }


@pytest.fixture
def yarn_logs():
    """Provide YARN-specific log content."""
    return {
        '/var/log/yarn/resourcemanager.log': (
            "2025-01-15 10:00:00 ERROR ResourceManager: NodeUnhealthy: node02\n"
            "2025-01-15 10:01:00 ERROR Container container_123 is running beyond physical memory limits\n"
            "2025-01-15 10:02:00 WARN preempting container container_456\n"
            "2025-01-15 10:03:00 ERROR Application app_001 failed 3 times\n"
        ),
    }


@pytest.fixture
def jvm_logs():
    """Provide JVM-specific log content."""
    return {
        '/var/log/hadoop/hdfs-namenode.log': (
            "2025-01-15 10:00:00 ERROR OutOfMemoryError: Java heap space\n"
            "2025-01-15 10:01:00 INFO GC pause (young) 150ms\n"
            "2025-01-15 10:02:00 ERROR GC overhead limit exceeded\n"
        ),
    }


@pytest.fixture
def security_logs():
    """Provide security-specific log content."""
    return {
        '/var/log/hadoop/hdfs-namenode.log': (
            "2025-01-15 10:00:00 ERROR GSS initiate failed\n"
            "2025-01-15 10:01:00 ERROR javax.security.auth.login.LoginException: unable to login\n"
        ),
    }


@pytest.fixture
def zk_logs():
    """Provide ZooKeeper-specific log content."""
    return {
        '/var/log/zookeeper/zookeeper.log': (
            "2025-01-15 10:00:00 ERROR Session 0x123abc has expired\n"
            "2025-01-15 10:01:00 WARN Connection loss to zk-server:2181\n"
        ),
    }


@pytest.fixture
def temporal_logs():
    """Provide logs with temporal spikes for testing."""
    lines = []
    # Normal rate: 1 error per 5-min bucket for hours 09-10
    for h in range(9, 11):
        for m in range(0, 60, 5):
            lines.append(f"2025-01-15 {h:02d}:{m:02d}:00 ERROR something failed\n")

    # Spike: 20 errors in the 11:00-11:05 bucket
    for i in range(20):
        lines.append(f"2025-01-15 11:00:{i:02d} ERROR something failed\n")

    # Back to normal
    for m in range(5, 60, 5):
        lines.append(f"2025-01-15 11:{m:02d}:00 ERROR something failed\n")

    return {'/var/log/test.log': ''.join(lines)}


@pytest.fixture
def master_config(tmp_dir):
    """Provide a test master configuration."""
    config = {
        'collection_enabled': True,
        'auto_send_enabled': True,
        'send_frequency': 'weekly',
        'support_endpoint': 'https://support.odp.com/upload',
        'support_token': 'test-token',
        'hdfs_path': '/odpsc/diagnostics',
        'hdfs_archive_enabled': False,
        'master_port': 8085,
        'admin_username': 'admin',
        'admin_password': 'admin',
        'admin_password_hash': '',
        'api_key': 'test-api-key-12345',
        'encryption_key': '',
        'max_upload_size_mb': 100,
        'max_bundle_size_mb': 500,
        'log_paths': [],
        'ambari_server_url': 'http://localhost:8080',
        'cluster_name': 'test-cluster',
        'gunicorn_workers': 2,
    }
    config_path = os.path.join(tmp_dir, 'master_config.json')
    with open(config_path, 'w') as f:
        json.dump(config, f)
    return config, config_path


@pytest.fixture
def agent_config(tmp_dir):
    """Provide a test agent configuration."""
    config = {
        'collection_enabled': True,
        'master_url': 'http://localhost:8085',
        'api_key': 'test-api-key-12345',
        'bundle_level': 'L1',
        'log_paths': [],
        'config_paths': [],
        'max_log_size_mb': 1,
        'log_retention_days': 7,
        'ambari_server_url': 'http://localhost:8080',
        'cluster_name': 'test-cluster',
    }
    config_path = os.path.join(tmp_dir, 'agent_config.json')
    with open(config_path, 'w') as f:
        json.dump(config, f)
    return config, config_path


@pytest.fixture
def master_app(master_config, tmp_dir, monkeypatch):
    """Provide a Flask test app for the ODPSC Master v2."""
    config, _ = master_config
    # Redirect storage dirs to tmp_dir
    monkeypatch.setattr('odpsc_master.BUNDLE_DIR', os.path.join(tmp_dir, 'bundles'))
    monkeypatch.setattr('odpsc_master.DB_DIR', os.path.join(tmp_dir, 'db'))
    monkeypatch.setattr('odpsc_master.DB_PATH', os.path.join(tmp_dir, 'db', 'bundles.db'))
    monkeypatch.setattr('odpsc_master.AGGREGATED_DIR', os.path.join(tmp_dir, 'aggregated'))
    monkeypatch.setattr('odpsc_master.CONFIG_PATH', os.path.join(tmp_dir, 'master_config.json'))

    from odpsc_master import create_app
    app = create_app(config)
    app.config['TESTING'] = True
    return app


@pytest.fixture
def client(master_app):
    """Provide a Flask test client."""
    return master_app.test_client()


@pytest.fixture
def auth_headers():
    """Provide Basic Auth headers for management endpoints."""
    import base64
    credentials = base64.b64encode(b'admin:admin').decode('utf-8')
    return {'Authorization': f'Basic {credentials}'}


@pytest.fixture
def api_key_headers():
    """Provide API key headers for agent upload endpoints."""
    return {
        'Authorization': 'Bearer test-api-key-12345',
        'X-ODPSC-Bundle-ID': 'test-bundle-id-001',
    }
