"""
Shared test fixtures for ODPSC tests.
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
def master_config(tmp_dir):
    """Provide a test master configuration."""
    config = {
        'collection_enabled': True,
        'auto_send_enabled': True,
        'send_frequency': 'weekly',
        'support_endpoint': 'https://support.odp.com/upload',
        'support_token': 'test-token',
        'hdfs_path': '/odpsc/diagnostics',
        'master_port': 8085,
        'admin_username': 'admin',
        'admin_password': 'admin',
        'encryption_key': '',
        'log_paths': [],
        'ambari_server_url': 'http://localhost:8080',
        'cluster_name': 'test-cluster',
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
        'master_url': 'http://localhost:8085/api/v1/submit_data',
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
def master_app(master_config):
    """Provide a Flask test client for the ODPSC Master."""
    config, _ = master_config
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
    """Provide Basic Auth headers for test requests."""
    import base64
    credentials = base64.b64encode(b'admin:admin').decode('utf-8')
    return {'Authorization': f'Basic {credentials}'}
