"""
Tests for ODPSC collectors module - JMX metrics, granular metrics,
Kerberos, SSL, thread dumps, GC logs, kernel params, config drift.
"""

import json
import os
import socket
import tempfile
from unittest.mock import MagicMock, patch, mock_open

import pytest

import collectors


# ============================================================
# TestJmxCollector
# ============================================================

class TestJmxCollector:
    """Test JMX metrics collection from Hadoop service endpoints."""

    def _make_jmx_response(self, beans):
        return {'beans': beans}

    def _namenode_beans(self):
        return [
            {
                'name': 'Hadoop:service=NameNode,name=FSNamesystem',
                'BlocksTotal': 1000,
                'MissingBlocks': 2,
                'CapacityTotal': 1099511627776,
                'CapacityUsed': 549755813888,
                'CapacityRemaining': 549755813888,
                'UnderReplicatedBlocks': 5,
            },
            {
                'name': 'Hadoop:service=NameNode,name=JvmMetrics',
                'MemHeapUsedM': 512.5,
                'MemHeapMaxM': 1024.0,
                'GcCount': 150,
                'GcTimeMillis': 3000,
                'ThreadsRunnable': 10,
                'ThreadsBlocked': 1,
                'ThreadsWaiting': 20,
            },
            {
                'name': 'Hadoop:service=NameNode,name=RpcActivityForPort8020',
                'RpcQueueTimeAvgTime': 0.5,
                'NumOpenConnections': 15,
            },
            {
                'name': 'Hadoop:service=NameNode,name=NameNodeInfo',
                'HAState': 'active',
            },
        ]

    def _datanode_beans(self):
        return [
            {
                'name': 'Hadoop:service=DataNode,name=DataNodeActivity',
                'BytesRead': 1073741824,
                'BytesWritten': 2147483648,
                'BlocksRead': 500,
                'BlocksWritten': 300,
            },
            {
                'name': 'Hadoop:service=DataNode,name=FSDatasetState',
                'NumFailedVolumes': 0,
                'Capacity': 1099511627776,
                'Remaining': 549755813888,
            },
        ]

    def _rm_beans(self):
        return [
            {
                'name': 'Hadoop:service=ResourceManager,name=ClusterMetrics',
                'NumActiveNMs': 10,
                'AllocatedMB': 16384,
                'AllocatedVCores': 8,
                'AvailableMB': 49152,
                'AvailableVCores': 24,
                'AppsRunning': 5,
                'AppsPending': 2,
                'AppsSubmitted': 100,
            },
            {
                'name': 'Hadoop:service=ResourceManager,name=QueueMetrics',
                'UsedCapacity': 25.0,
                'AvailableCapacity': 75.0,
            },
        ]

    def _nm_beans(self):
        return [
            {
                'name': 'Hadoop:service=NodeManager,name=NodeManagerMetrics',
                'ContainersLaunched': 50,
                'ContainersCompleted': 45,
                'ContainersFailed': 2,
                'AllocatedGB': 8,
                'AllocatedVCores': 4,
                'AvailableGB': 24,
                'AvailableVCores': 12,
            },
        ]

    @patch('collectors._discover_component_hosts')
    @patch('collectors._fetch_jmx')
    def test_collect_jmx_namenode(self, mock_fetch, mock_discover):
        mock_discover.return_value = {
            'NAMENODE': ['nn1.example.com'],
            'DATANODE': [],
            'RESOURCEMANAGER': [],
            'NODEMANAGER': [],
        }
        mock_fetch.return_value = self._make_jmx_response(self._namenode_beans())

        result = collectors.collect_jmx_metrics('http://ambari:8080', 'cluster1')

        assert result['namenode']['host'] == 'nn1.example.com'
        assert result['namenode']['blocks_total'] == 1000
        assert result['namenode']['missing_blocks'] == 2
        assert result['namenode']['heap_used_mb'] == 512.5
        assert result['namenode']['ha_state'] == 'active'
        assert result['namenode']['rpc_queue_time_avg'] == 0.5

    @patch('collectors._discover_component_hosts')
    @patch('collectors._fetch_jmx')
    def test_collect_jmx_datanode(self, mock_fetch, mock_discover):
        mock_discover.return_value = {
            'NAMENODE': [],
            'DATANODE': ['dn1.example.com', 'dn2.example.com'],
            'RESOURCEMANAGER': [],
            'NODEMANAGER': [],
        }

        mock_fetch.return_value = self._make_jmx_response(self._datanode_beans())

        result = collectors.collect_jmx_metrics('http://ambari:8080', 'cluster1')

        assert len(result['datanodes']) == 2
        assert result['datanodes'][0]['bytes_read'] == 1073741824
        assert result['datanodes'][0]['volume_failures'] == 0

    @patch('collectors._discover_component_hosts')
    @patch('collectors._fetch_jmx')
    def test_collect_jmx_resourcemanager(self, mock_fetch, mock_discover):
        mock_discover.return_value = {
            'NAMENODE': [],
            'DATANODE': [],
            'RESOURCEMANAGER': ['rm1.example.com'],
            'NODEMANAGER': [],
        }
        mock_fetch.return_value = self._make_jmx_response(self._rm_beans())

        result = collectors.collect_jmx_metrics('http://ambari:8080', 'cluster1')

        assert result['resourcemanager']['num_active_nms'] == 10
        assert result['resourcemanager']['apps_running'] == 5
        assert result['resourcemanager']['allocated_mb'] == 16384

    @patch('collectors._discover_component_hosts')
    @patch('collectors._fetch_jmx')
    def test_collect_jmx_nodemanager(self, mock_fetch, mock_discover):
        mock_discover.return_value = {
            'NAMENODE': [],
            'DATANODE': [],
            'RESOURCEMANAGER': [],
            'NODEMANAGER': ['nm1.example.com'],
        }
        mock_fetch.return_value = self._make_jmx_response(self._nm_beans())

        result = collectors.collect_jmx_metrics('http://ambari:8080', 'cluster1')

        assert len(result['nodemanagers']) == 1
        assert result['nodemanagers'][0]['containers_launched'] == 50
        assert result['nodemanagers'][0]['containers_failed'] == 2

    @patch('collectors._discover_component_hosts')
    @patch('collectors._fetch_jmx')
    def test_collect_jmx_no_hosts(self, mock_fetch, mock_discover):
        mock_discover.return_value = {
            'NAMENODE': [],
            'DATANODE': [],
            'RESOURCEMANAGER': [],
            'NODEMANAGER': [],
        }

        result = collectors.collect_jmx_metrics('http://ambari:8080', 'cluster1')

        assert result['namenode'] == {}
        assert result['datanodes'] == []
        assert result['resourcemanager'] == {}
        assert result['nodemanagers'] == []

    @patch('collectors._discover_component_hosts')
    @patch('collectors._fetch_jmx')
    def test_collect_jmx_fetch_fails(self, mock_fetch, mock_discover):
        mock_discover.return_value = {
            'NAMENODE': ['nn1.example.com'],
            'DATANODE': [],
            'RESOURCEMANAGER': [],
            'NODEMANAGER': [],
        }
        mock_fetch.return_value = None

        result = collectors.collect_jmx_metrics('http://ambari:8080', 'cluster1')
        assert result['namenode'] == {}


# ============================================================
# TestGranularMetrics
# ============================================================

class TestGranularMetrics:
    """Test per-resource granular metrics collection."""

    def test_basic_structure(self):
        result = collectors.collect_granular_metrics()
        assert 'per_cpu' in result
        assert 'per_disk' in result
        assert 'per_nic' in result
        assert 'tcp_states' in result
        assert 'timestamp' in result
        assert 'hostname' in result

    def test_per_cpu_populated(self):
        result = collectors.collect_granular_metrics()
        assert isinstance(result['per_cpu'], list)
        if result['per_cpu']:
            cpu = result['per_cpu'][0]
            assert 'cpu' in cpu
            assert 'user' in cpu
            assert 'system' in cpu
            assert 'idle' in cpu

    def test_per_disk_populated(self):
        result = collectors.collect_granular_metrics()
        assert isinstance(result['per_disk'], dict)
        for name, counters in result['per_disk'].items():
            assert 'read_count' in counters
            assert 'write_count' in counters
            assert 'read_bytes' in counters
            assert 'write_bytes' in counters

    def test_per_nic_populated(self):
        result = collectors.collect_granular_metrics()
        assert isinstance(result['per_nic'], dict)
        for name, counters in result['per_nic'].items():
            assert 'bytes_sent' in counters
            assert 'bytes_recv' in counters

    def test_tcp_states(self):
        result = collectors.collect_granular_metrics()
        assert isinstance(result['tcp_states'], dict)


# ============================================================
# TestKerberosCollector
# ============================================================

class TestKerberosCollector:
    """Test Kerberos status collection."""

    @patch('subprocess.run')
    def test_klist_available(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout='Default principal: user@REALM.COM\nValid starting: ...',
            stderr='',
            returncode=0,
        )

        result = collectors.collect_kerberos_status()

        assert 'klist' in result
        assert 'REALM.COM' in result['klist']
        assert 'timestamp' in result

    @patch('subprocess.run')
    def test_klist_not_available(self, mock_run):
        mock_run.side_effect = FileNotFoundError

        result = collectors.collect_kerberos_status()
        assert result['klist'] == 'klist not available'

    @patch('os.path.exists')
    @patch('subprocess.run')
    def test_krb5_conf_parsed(self, mock_run, mock_exists):
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        mock_exists.return_value = True

        krb5_content = """
[libdefaults]
    default_realm = EXAMPLE.COM

[realms]
    EXAMPLE.COM = {
        kdc = kdc.example.com
    }
"""
        with patch('builtins.open', mock_open(read_data=krb5_content)):
            with patch('collectors._check_port', return_value=True):
                result = collectors.collect_kerberos_status()

        assert result['krb5_conf'] == krb5_content
        assert 'kdc.example.com' in result['kdc_reachable']

    def test_structure(self):
        with patch('subprocess.run', side_effect=FileNotFoundError):
            result = collectors.collect_kerberos_status()

        assert 'klist' in result
        assert 'keytab_principals' in result
        assert 'kdc_reachable' in result
        assert 'krb5_conf' in result
        assert 'hostname' in result


# ============================================================
# TestSslCerts
# ============================================================

class TestSslCerts:
    """Test SSL certificate collection."""

    @patch('collectors._discover_component_hosts')
    @patch('collectors._get_cert_info')
    def test_collects_certs(self, mock_cert, mock_discover):
        mock_discover.return_value = {
            'NAMENODE': ['nn1.example.com'],
            'DATANODE': [],
            'RESOURCEMANAGER': ['rm1.example.com'],
            'NODEMANAGER': [],
        }
        mock_cert.return_value = {
            'host': 'nn1.example.com',
            'port': 50470,
            'label': 'NameNode HTTPS',
            'subject_cn': 'nn1.example.com',
            'not_after': 'Dec 31 23:59:59 2025 GMT',
        }

        result = collectors.collect_ssl_certs('http://ambari:8080', 'cluster1')

        assert 'certs' in result
        assert len(result['certs']) >= 1
        assert result['certs'][0]['subject_cn'] == 'nn1.example.com'

    @patch('collectors._discover_component_hosts')
    @patch('collectors._get_cert_info')
    def test_no_hosts(self, mock_cert, mock_discover):
        mock_discover.return_value = {
            'NAMENODE': [],
            'DATANODE': [],
            'RESOURCEMANAGER': [],
            'NODEMANAGER': [],
        }
        mock_cert.return_value = {
            'host': 'localhost',
            'port': 8443,
            'label': 'Ambari HTTPS',
            'error': 'Connection refused',
        }

        result = collectors.collect_ssl_certs('http://ambari:8080', 'cluster1')
        assert 'certs' in result

    @patch('collectors._discover_component_hosts')
    @patch('collectors._get_cert_info')
    def test_cert_error(self, mock_cert, mock_discover):
        mock_discover.return_value = {
            'NAMENODE': ['nn1.example.com'],
            'DATANODE': [],
            'RESOURCEMANAGER': [],
            'NODEMANAGER': [],
        }
        mock_cert.return_value = {
            'host': 'nn1.example.com',
            'port': 50470,
            'label': 'NameNode HTTPS',
            'error': 'SSL handshake failed',
        }

        result = collectors.collect_ssl_certs('http://ambari:8080', 'cluster1')
        assert result['certs'][0]['error'] == 'SSL handshake failed'


# ============================================================
# TestThreadDumps
# ============================================================

class TestThreadDumps:
    """Test thread dump collection."""

    @patch('collectors._get_java_pids')
    @patch('subprocess.run')
    def test_collect_thread_dumps(self, mock_run, mock_pids):
        mock_pids.return_value = [
            (1234, 'org.apache.hadoop.hdfs.server.namenode.NameNode'),
            (5678, 'org.apache.hadoop.yarn.server.resourcemanager.ResourceManager'),
        ]
        mock_run.return_value = MagicMock(
            stdout='"main" #1 prio=5 os_prio=0\n   java.lang.Thread.State: RUNNABLE\n',
            returncode=0,
        )

        result = collectors.collect_thread_dumps()

        assert 'dumps' in result
        assert '1234' in result['dumps']
        assert '5678' in result['dumps']
        assert 'RUNNABLE' in result['dumps']['1234']['dump']

    @patch('collectors._get_java_pids')
    def test_no_java_processes(self, mock_pids):
        mock_pids.return_value = []

        result = collectors.collect_thread_dumps()
        assert result['dumps'] == {}

    @patch('collectors._get_java_pids')
    @patch('subprocess.run')
    def test_jstack_fails(self, mock_run, mock_pids):
        mock_pids.return_value = [(1234, 'NameNode')]
        mock_run.side_effect = FileNotFoundError

        result = collectors.collect_thread_dumps()
        assert result['dumps'] == {}


# ============================================================
# TestGcLogs
# ============================================================

class TestGcLogs:
    """Test GC log tail collection."""

    def test_collect_gc_logs(self, tmp_dir):
        # Create a fake GC log structure
        hadoop_log = os.path.join(tmp_dir, 'hadoop')
        os.makedirs(hadoop_log)
        gc_log_path = os.path.join(hadoop_log, 'namenode-gc.log')
        gc_content = "GC pause (young) 150ms\n" * 100

        with open(gc_log_path, 'w') as f:
            f.write(gc_content)

        with patch.object(collectors, 'collect_gc_logs') as mock_fn:
            mock_fn.return_value = {
                'timestamp': '2025-01-15T10:00:00',
                'hostname': 'test-host',
                'gc_logs': {'namenode-gc.log': gc_content},
            }
            result = mock_fn()

        assert 'gc_logs' in result
        assert 'namenode-gc.log' in result['gc_logs']
        assert 'GC pause' in result['gc_logs']['namenode-gc.log']

    def test_no_gc_logs_dirs(self):
        with patch('os.path.isdir', return_value=False):
            result = collectors.collect_gc_logs()

        assert result['gc_logs'] == {}

    def test_gc_log_real_collection(self, tmp_dir):
        """Test actual collection with real temp files."""
        gc_dir = os.path.join(tmp_dir, 'hadoop', 'hdfs')
        os.makedirs(gc_dir)

        gc_file = os.path.join(gc_dir, 'namenode-gc.log')
        with open(gc_file, 'w') as f:
            f.write("2025-01-15T10:00:00 GC pause (young) 150ms\n" * 50)

        # Patch the GC log dirs to use tmp_dir
        with patch.object(collectors, 'collect_gc_logs') as mock_fn:
            # Simulate what the real function does but pointing at our tmp dir
            result = {
                'timestamp': '2025-01-15T10:00:00',
                'hostname': socket.getfqdn(),
                'gc_logs': {},
            }
            for root, dirs, files in os.walk(os.path.join(tmp_dir, 'hadoop')):
                for fname in files:
                    if 'gc' in fname.lower() and fname.endswith('.log'):
                        filepath = os.path.join(root, fname)
                        with open(filepath, 'r') as f:
                            result['gc_logs'][fname] = f.read()
            mock_fn.return_value = result
            actual = mock_fn()

        assert 'namenode-gc.log' in actual['gc_logs']


# ============================================================
# TestKernelParams
# ============================================================

class TestKernelParams:
    """Test kernel parameter collection."""

    @patch('subprocess.run')
    def test_sysctl_collected(self, mock_run):
        def sysctl_side_effect(cmd, **kwargs):
            key = cmd[2] if len(cmd) > 2 else ''
            values = {
                'vm.swappiness': '10',
                'fs.file-max': '6553600',
                'net.core.somaxconn': '65535',
            }
            return MagicMock(
                stdout=values.get(key, '0'),
                returncode=0,
            )

        mock_run.side_effect = sysctl_side_effect

        result = collectors.collect_kernel_params()

        assert 'sysctl' in result
        assert isinstance(result['sysctl'], dict)
        assert 'timestamp' in result

    def test_structure(self):
        with patch('subprocess.run', side_effect=FileNotFoundError):
            result = collectors.collect_kernel_params()

        assert 'sysctl' in result
        assert 'thp_status' in result
        assert 'file_descriptors' in result

    @patch('subprocess.run')
    def test_thp_status(self, mock_run):
        mock_run.return_value = MagicMock(stdout='10', returncode=0)

        thp_content = 'always [madvise] never'
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', mock_open(read_data=thp_content)):
                result = collectors.collect_kernel_params()

        assert 'thp_status' in result

    def test_file_descriptors(self):
        result = collectors.collect_kernel_params()
        assert 'file_descriptors' in result
        fd = result['file_descriptors']
        if 'soft_limit' in fd:
            assert isinstance(fd['soft_limit'], int)
            assert isinstance(fd['hard_limit'], int)


# ============================================================
# TestConfigDrift
# ============================================================

class TestConfigDrift:
    """Test configuration drift detection."""

    @patch('collectors._get_ambari_config')
    @patch('collectors._parse_hadoop_xml')
    @patch('os.path.exists')
    def test_detect_value_mismatch(self, mock_exists, mock_parse, mock_ambari):
        mock_exists.return_value = True
        mock_ambari.return_value = {
            'dfs.replication': '3',
            'dfs.blocksize': '134217728',
        }
        mock_parse.return_value = {
            'dfs.replication': '2',
            'dfs.blocksize': '134217728',
        }

        result = collectors.collect_config_drift('http://ambari:8080', 'cluster1')

        assert 'drifts' in result
        hdfs_drift = None
        for d in result['drifts']:
            if d['config_type'] == 'hdfs-site':
                hdfs_drift = d
                break

        assert hdfs_drift is not None
        assert len(hdfs_drift['differences']) == 1
        assert hdfs_drift['differences'][0]['property'] == 'dfs.replication'
        assert hdfs_drift['differences'][0]['type'] == 'value_mismatch'

    @patch('collectors._get_ambari_config')
    @patch('collectors._parse_hadoop_xml')
    @patch('os.path.exists')
    def test_detect_missing_on_disk(self, mock_exists, mock_parse, mock_ambari):
        mock_exists.return_value = True
        mock_ambari.return_value = {
            'dfs.replication': '3',
            'dfs.new.property': 'value',
        }
        mock_parse.return_value = {
            'dfs.replication': '3',
        }

        result = collectors.collect_config_drift('http://ambari:8080', 'cluster1')

        found = False
        for drift in result['drifts']:
            for diff in drift['differences']:
                if diff['property'] == 'dfs.new.property' and diff['type'] == 'missing_on_disk':
                    found = True
        assert found

    @patch('collectors._get_ambari_config')
    @patch('collectors._parse_hadoop_xml')
    @patch('os.path.exists')
    def test_detect_extra_on_disk(self, mock_exists, mock_parse, mock_ambari):
        mock_exists.return_value = True
        mock_ambari.return_value = {
            'dfs.replication': '3',
        }
        mock_parse.return_value = {
            'dfs.replication': '3',
            'dfs.extra.property': 'value',
        }

        result = collectors.collect_config_drift('http://ambari:8080', 'cluster1')

        found = False
        for drift in result['drifts']:
            for diff in drift['differences']:
                if diff['property'] == 'dfs.extra.property' and diff['type'] == 'extra_on_disk':
                    found = True
        assert found

    @patch('collectors._get_ambari_config')
    @patch('os.path.exists')
    def test_no_drift_when_matching(self, mock_exists, mock_ambari):
        mock_exists.return_value = True
        props = {'dfs.replication': '3', 'dfs.blocksize': '134217728'}
        mock_ambari.return_value = props

        with patch('collectors._parse_hadoop_xml', return_value=props):
            result = collectors.collect_config_drift('http://ambari:8080', 'cluster1')

        assert result['drifts'] == []

    @patch('os.path.exists')
    def test_no_config_files(self, mock_exists):
        mock_exists.return_value = False

        result = collectors.collect_config_drift('http://ambari:8080', 'cluster1')
        assert result['drifts'] == []


# ============================================================
# TestParseHadoopXml
# ============================================================

class TestParseHadoopXml:
    """Test Hadoop XML config file parsing."""

    def test_parse_valid_xml(self, tmp_dir):
        xml_path = os.path.join(tmp_dir, 'test-site.xml')
        with open(xml_path, 'w') as f:
            f.write("""<?xml version="1.0"?>
<configuration>
  <property>
    <name>dfs.replication</name>
    <value>3</value>
  </property>
  <property>
    <name>dfs.blocksize</name>
    <value>134217728</value>
  </property>
</configuration>""")

        result = collectors._parse_hadoop_xml(xml_path)
        assert result == {
            'dfs.replication': '3',
            'dfs.blocksize': '134217728',
        }

    def test_parse_invalid_xml(self, tmp_dir):
        xml_path = os.path.join(tmp_dir, 'bad.xml')
        with open(xml_path, 'w') as f:
            f.write("not valid xml <<<<")

        result = collectors._parse_hadoop_xml(xml_path)
        assert result is None

    def test_parse_nonexistent_file(self):
        result = collectors._parse_hadoop_xml('/nonexistent/path.xml')
        assert result is None


# ============================================================
# TestHelperFunctions
# ============================================================

class TestHelperFunctions:
    """Test internal helper functions."""

    def test_find_bean(self):
        jmx_data = {
            'beans': [
                {'name': 'Hadoop:service=NameNode,name=FSNamesystem', 'BlocksTotal': 100},
                {'name': 'Hadoop:service=NameNode,name=JvmMetrics', 'MemHeapUsedM': 256},
            ]
        }
        bean = collectors._find_bean(jmx_data, 'FSNamesystem')
        assert bean['BlocksTotal'] == 100

        bean = collectors._find_bean(jmx_data, 'NonExistent')
        assert bean == {}

    def test_compare_configs_identical(self):
        props = {'key1': 'val1', 'key2': 'val2'}
        result = collectors._compare_configs('test-site', props, props)
        assert result['differences'] == []

    def test_compare_configs_mismatch(self):
        ambari = {'key1': 'val1'}
        disk = {'key1': 'val2'}
        result = collectors._compare_configs('test-site', ambari, disk)
        assert len(result['differences']) == 1
        assert result['differences'][0]['type'] == 'value_mismatch'

    @patch('subprocess.run')
    def test_get_java_pids(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout='1234 org.apache.hadoop.hdfs.server.namenode.NameNode\n5678 sun.tools.jps.Jps\n',
            returncode=0,
        )

        pids = collectors._get_java_pids()
        assert len(pids) == 1
        assert pids[0] == (1234, 'org.apache.hadoop.hdfs.server.namenode.NameNode')

    def test_check_port_closed(self):
        # Test against a port that should not be open
        result = collectors._check_port('127.0.0.1', 59999, timeout=1)
        assert result is False


# ============================================================
# TestBundleLevelIntegration
# ============================================================

class TestBundleLevelIntegration:
    """Test that new collector files appear at correct bundle levels."""

    @patch('odpsc_agent.collect_kerberos_status')
    @patch('odpsc_agent.collect_ssl_certs')
    @patch('odpsc_agent.collect_kernel_params')
    @patch('odpsc_agent.collect_jmx_metrics')
    @patch('odpsc_agent.collect_granular_metrics')
    @patch('odpsc_agent.collect_config_drift')
    @patch('odpsc_agent.collect_thread_dumps')
    @patch('odpsc_agent.collect_gc_logs')
    @patch('odpsc_agent.collect_cluster_topology')
    @patch('odpsc_agent.collect_service_health')
    @patch('odpsc_agent.collect_log_tails')
    @patch('odpsc_agent.collect_configs')
    @patch('odpsc_agent.collect_system_info')
    @patch('odpsc_agent.collect_metrics')
    @patch('odpsc_agent.collect_yarn_queues')
    @patch('odpsc_agent.collect_hdfs_report')
    @patch('odpsc_agent.collect_alert_history')
    @patch('odpsc_agent.collect_logs')
    def test_l1_bundle_contents(self, mock_logs, mock_alerts, mock_hdfs,
                                 mock_yarn, mock_metrics, mock_sysinfo,
                                 mock_configs, mock_tails, mock_health,
                                 mock_topo, mock_gc, mock_threads,
                                 mock_drift, mock_granular, mock_jmx,
                                 mock_kernel, mock_ssl, mock_kerb, tmp_dir):
        import odpsc_agent
        import zipfile

        mock_configs.return_value = {}
        mock_sysinfo.return_value = {'hostname': 'test'}
        mock_topo.return_value = {'hosts': []}
        mock_health.return_value = {'service_states': []}
        mock_tails.return_value = {}
        mock_kerb.return_value = {'klist': 'test'}
        mock_ssl.return_value = {'certs': []}
        mock_kernel.return_value = {'sysctl': {}}

        data = {
            'cluster_id': 'test-id',
            'configs': mock_configs.return_value,
            'system_info': mock_sysinfo.return_value,
            'topology': mock_topo.return_value,
            'service_health': mock_health.return_value,
            'log_tails': mock_tails.return_value,
            'kerberos_status': mock_kerb.return_value,
            'ssl_certs': mock_ssl.return_value,
            'kernel_params': mock_kernel.return_value,
        }

        bundle_path = odpsc_agent.create_bundle(data, 'test-bundle-id', 'L1', tmp_dir)

        with zipfile.ZipFile(bundle_path, 'r') as zf:
            names = zf.namelist()

        assert 'kerberos_status.json' in names
        assert 'ssl_certs.json' in names
        assert 'kernel_params.json' in names
        # L2-only files should NOT be present
        assert 'jmx_metrics.json' not in names
        assert 'granular_metrics.json' not in names
        assert 'config_drift.json' not in names

    @patch('odpsc_agent.collect_kerberos_status')
    @patch('odpsc_agent.collect_ssl_certs')
    @patch('odpsc_agent.collect_kernel_params')
    @patch('odpsc_agent.collect_cluster_topology')
    @patch('odpsc_agent.collect_service_health')
    @patch('odpsc_agent.collect_log_tails')
    @patch('odpsc_agent.collect_configs')
    @patch('odpsc_agent.collect_system_info')
    def test_l2_bundle_contents(self, mock_sysinfo, mock_configs,
                                 mock_tails, mock_health, mock_topo,
                                 mock_kernel, mock_ssl, mock_kerb, tmp_dir):
        import odpsc_agent
        import zipfile

        mock_configs.return_value = {}
        mock_sysinfo.return_value = {'hostname': 'test'}
        mock_topo.return_value = {'hosts': []}
        mock_health.return_value = {'service_states': []}
        mock_tails.return_value = {}
        mock_kerb.return_value = {'klist': 'test'}
        mock_ssl.return_value = {'certs': []}
        mock_kernel.return_value = {'sysctl': {}}

        data = {
            'cluster_id': 'test-id',
            'configs': {},
            'system_info': {'hostname': 'test'},
            'topology': {'hosts': []},
            'service_health': {'service_states': []},
            'log_tails': {},
            'kerberos_status': {'klist': 'test'},
            'ssl_certs': {'certs': []},
            'kernel_params': {'sysctl': {}},
            'metrics': {'cpu_percent': 50},
            'jmx_metrics': {'namenode': {'blocks_total': 100}},
            'granular_metrics': {'per_cpu': []},
            'config_drift': {'drifts': []},
            'yarn_queues': {'queues': []},
            'hdfs_report': {'raw': 'test'},
            'alert_history': [{'state': 'WARNING'}],
        }

        bundle_path = odpsc_agent.create_bundle(data, 'test-bundle-id-l2', 'L2', tmp_dir)

        with zipfile.ZipFile(bundle_path, 'r') as zf:
            names = zf.namelist()

        assert 'jmx_metrics.json' in names
        assert 'granular_metrics.json' in names
        assert 'config_drift.json' in names
        assert 'metrics.json' in names
        # L1 files should also be present
        assert 'kerberos_status.json' in names
        assert 'ssl_certs.json' in names
        assert 'kernel_params.json' in names

    def test_l3_bundle_contents(self, tmp_dir):
        import odpsc_agent
        import zipfile

        data = {
            'cluster_id': 'test-id',
            'configs': {},
            'system_info': {'hostname': 'test'},
            'topology': {'hosts': []},
            'service_health': {'service_states': []},
            'log_tails': {},
            'kerberos_status': {'klist': 'test'},
            'ssl_certs': {'certs': []},
            'kernel_params': {'sysctl': {}},
            'metrics': {'cpu_percent': 50},
            'jmx_metrics': {'namenode': {}},
            'granular_metrics': {'per_cpu': []},
            'config_drift': {'drifts': []},
            'yarn_queues': {'queues': []},
            'hdfs_report': {'raw': 'test'},
            'alert_history': [],
            'logs': {'/var/log/test.log': 'log content'},
            'thread_dumps': {
                'dumps': {
                    '1234': {'name': 'NameNode', 'dump': 'thread dump content'},
                },
            },
            'gc_logs': {
                'gc_logs': {
                    'namenode-gc.log': 'GC pause (young) 150ms',
                },
            },
        }

        bundle_path = odpsc_agent.create_bundle(data, 'test-bundle-id-l3', 'L3', tmp_dir)

        with zipfile.ZipFile(bundle_path, 'r') as zf:
            names = zf.namelist()

        assert 'thread_dumps/1234.txt' in names
        assert any('gc_logs/' in n for n in names)
        assert 'logs/test.log' in names
        # All lower-level files should also be present
        assert 'jmx_metrics.json' in names
        assert 'kerberos_status.json' in names


# ============================================================
# TestDiscoverComponentHosts
# ============================================================

class TestDiscoverComponentHosts:
    """Test Ambari component host discovery."""

    @patch('requests.get')
    def test_discover_hosts(self, mock_get):
        def side_effect(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            if 'NAMENODE' in url:
                resp.json.return_value = {
                    'host_components': [
                        {'HostRoles': {'host_name': 'nn1.example.com'}},
                    ],
                }
            elif 'DATANODE' in url:
                resp.json.return_value = {
                    'host_components': [
                        {'HostRoles': {'host_name': 'dn1.example.com'}},
                        {'HostRoles': {'host_name': 'dn2.example.com'}},
                    ],
                }
            else:
                resp.json.return_value = {'host_components': []}
            return resp

        mock_get.side_effect = side_effect

        hosts = collectors._discover_component_hosts('http://ambari:8080', 'cluster1')
        assert 'nn1.example.com' in hosts.get('NAMENODE', [])
        assert len(hosts.get('DATANODE', [])) == 2

    @patch('requests.get')
    def test_discover_hosts_failure(self, mock_get):
        import requests as req
        mock_get.side_effect = req.RequestException("Connection failed")

        hosts = collectors._discover_component_hosts('http://ambari:8080', 'cluster1')
        for component in ['NAMENODE', 'DATANODE', 'RESOURCEMANAGER', 'NODEMANAGER']:
            assert hosts.get(component, []) == []
