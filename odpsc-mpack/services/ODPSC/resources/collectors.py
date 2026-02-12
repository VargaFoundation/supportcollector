"""
ODPSC Collectors v2.2 - Deep diagnostic collectors for enhanced cluster monitoring.

Provides 8 collector functions for JMX metrics, granular system metrics,
Kerberos/SSL status, thread dumps, GC logs, kernel parameters, and config drift.
"""

import json
import logging
import os
import re
import ssl
import socket
import subprocess
from datetime import datetime, timezone
from xml.etree import ElementTree

import psutil
import requests

logger = logging.getLogger('odpsc-collectors')


def collect_jmx_metrics(ambari_url, cluster_name):
    """
    Collect JMX metrics from Hadoop service HTTP endpoints.

    Queries NameNode, DataNode, ResourceManager, and NodeManager JMX endpoints
    to gather heap, GC, blocks, RPC, HA state, and container metrics.

    Args:
        ambari_url: Ambari server URL for host/port discovery.
        cluster_name: Ambari cluster name.

    Returns:
        dict with keys: namenode, datanodes, resourcemanager, nodemanagers, timestamp.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'namenode': {},
        'datanodes': [],
        'resourcemanager': {},
        'nodemanagers': [],
    }

    hosts = _discover_component_hosts(ambari_url, cluster_name)

    # NameNode JMX
    nn_hosts = hosts.get('NAMENODE', [])
    for host in nn_hosts:
        jmx = _fetch_jmx(host, [9870, 50070])
        if jmx:
            result['namenode'] = _parse_namenode_jmx(jmx, host)
            break

    # DataNode JMX
    dn_hosts = hosts.get('DATANODE', [])
    for host in dn_hosts:
        jmx = _fetch_jmx(host, [9864, 50075])
        if jmx:
            result['datanodes'].append(_parse_datanode_jmx(jmx, host))

    # ResourceManager JMX
    rm_hosts = hosts.get('RESOURCEMANAGER', [])
    for host in rm_hosts:
        jmx = _fetch_jmx(host, [8088])
        if jmx:
            result['resourcemanager'] = _parse_resourcemanager_jmx(jmx, host)
            break

    # NodeManager JMX
    nm_hosts = hosts.get('NODEMANAGER', [])
    for host in nm_hosts:
        jmx = _fetch_jmx(host, [8042])
        if jmx:
            result['nodemanagers'].append(_parse_nodemanager_jmx(jmx, host))

    return result


def collect_granular_metrics():
    """
    Collect per-resource granular system metrics via psutil.

    Returns:
        dict with keys: per_cpu, per_disk, per_nic, tcp_states, timestamp.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'per_cpu': [],
        'per_disk': {},
        'per_nic': {},
        'tcp_states': {},
    }

    # Per-CPU times
    try:
        cpu_times = psutil.cpu_times_percent(interval=1, percpu=True)
        for i, ct in enumerate(cpu_times):
            result['per_cpu'].append({
                'cpu': i,
                'user': ct.user,
                'system': ct.system,
                'idle': ct.idle,
                'iowait': getattr(ct, 'iowait', 0),
            })
    except Exception as e:
        logger.warning("Failed to collect per-CPU metrics: %s", e)

    # Per-disk I/O
    try:
        disk_io = psutil.disk_io_counters(perdisk=True)
        if disk_io:
            for name, counters in disk_io.items():
                result['per_disk'][name] = {
                    'read_count': counters.read_count,
                    'write_count': counters.write_count,
                    'read_bytes': counters.read_bytes,
                    'write_bytes': counters.write_bytes,
                    'read_time': counters.read_time,
                    'write_time': counters.write_time,
                }
    except Exception as e:
        logger.warning("Failed to collect per-disk metrics: %s", e)

    # Per-NIC stats
    try:
        net_io = psutil.net_io_counters(pernic=True)
        if net_io:
            for name, counters in net_io.items():
                result['per_nic'][name] = {
                    'bytes_sent': counters.bytes_sent,
                    'bytes_recv': counters.bytes_recv,
                    'packets_sent': counters.packets_sent,
                    'packets_recv': counters.packets_recv,
                    'errin': counters.errin,
                    'errout': counters.errout,
                    'dropin': counters.dropin,
                    'dropout': counters.dropout,
                }
    except Exception as e:
        logger.warning("Failed to collect per-NIC metrics: %s", e)

    # TCP connection states
    try:
        connections = psutil.net_connections(kind='tcp')
        states = {}
        for conn in connections:
            state = conn.status
            states[state] = states.get(state, 0) + 1
        result['tcp_states'] = states
    except (psutil.AccessDenied, Exception) as e:
        logger.warning("Failed to collect TCP states: %s", e)

    return result


def collect_kerberos_status():
    """
    Collect Kerberos configuration and status.

    Returns:
        dict with keys: klist, keytab_principals, kdc_reachable, krb5_conf, timestamp.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'klist': '',
        'keytab_principals': [],
        'kdc_reachable': None,
        'krb5_conf': '',
    }

    # klist output
    try:
        proc = subprocess.run(
            ['klist', '-e'], capture_output=True, text=True, timeout=10,
        )
        result['klist'] = proc.stdout.strip() if proc.stdout else proc.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        result['klist'] = 'klist not available'

    # Keytab principals
    keytab_paths = ['/etc/security/keytabs']
    for kdir in keytab_paths:
        if os.path.isdir(kdir):
            for fname in os.listdir(kdir):
                if fname.endswith('.keytab'):
                    kt_path = os.path.join(kdir, fname)
                    try:
                        proc = subprocess.run(
                            ['klist', '-kt', kt_path],
                            capture_output=True, text=True, timeout=10,
                        )
                        if proc.stdout:
                            principals = set()
                            for line in proc.stdout.strip().split('\n'):
                                parts = line.strip().split()
                                if len(parts) >= 4 and '/' in parts[-1]:
                                    principals.add(parts[-1])
                            result['keytab_principals'].append({
                                'keytab': kt_path,
                                'principals': list(principals),
                            })
                    except (FileNotFoundError, subprocess.TimeoutExpired):
                        pass

    # KDC reachability
    try:
        krb5_path = '/etc/krb5.conf'
        if os.path.exists(krb5_path):
            with open(krb5_path, 'r') as f:
                content = f.read()
            result['krb5_conf'] = content

            kdc_hosts = re.findall(r'kdc\s*=\s*(\S+)', content, re.IGNORECASE)
            result['kdc_reachable'] = {}
            for kdc in kdc_hosts:
                host = kdc.split(':')[0]
                port = int(kdc.split(':')[1]) if ':' in kdc else 88
                result['kdc_reachable'][kdc] = _check_port(host, port, timeout=5)
    except Exception as e:
        logger.warning("Failed to check KDC reachability: %s", e)

    return result


def collect_ssl_certs(ambari_url, cluster_name):
    """
    Collect SSL certificate expiry for HTTPS service endpoints.

    Checks NameNode (50470), ResourceManager (8090), and Ambari (8443).

    Args:
        ambari_url: Ambari server URL.
        cluster_name: Ambari cluster name.

    Returns:
        dict with keys: certs (list of cert info dicts), timestamp.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'certs': [],
    }

    hosts = _discover_component_hosts(ambari_url, cluster_name)

    endpoints = []
    for nn in hosts.get('NAMENODE', []):
        endpoints.append((nn, 50470, 'NameNode HTTPS'))
    for rm in hosts.get('RESOURCEMANAGER', []):
        endpoints.append((rm, 8090, 'ResourceManager HTTPS'))

    # Ambari server
    try:
        from urllib.parse import urlparse
        parsed = urlparse(ambari_url)
        ambari_host = parsed.hostname or 'localhost'
        endpoints.append((ambari_host, 8443, 'Ambari HTTPS'))
    except Exception:
        pass

    for host, port, label in endpoints:
        cert_info = _get_cert_info(host, port, label)
        if cert_info:
            result['certs'].append(cert_info)

    return result


def collect_thread_dumps():
    """
    Collect thread dumps via jstack for all running Java processes.

    Returns:
        dict with keys: dumps (dict pid->dump), timestamp.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'dumps': {},
    }

    java_pids = _get_java_pids()
    for pid, name in java_pids:
        try:
            proc = subprocess.run(
                ['jstack', '-l', str(pid)],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode == 0 and proc.stdout:
                result['dumps'][str(pid)] = {
                    'name': name,
                    'dump': proc.stdout[:500000],  # Cap at 500KB per dump
                }
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.warning("Failed to get thread dump for PID %s: %s", pid, e)

    return result


def collect_gc_logs():
    """
    Collect tails of GC log files from standard Hadoop/HBase log directories.

    Returns:
        dict with keys: gc_logs (dict name->content), timestamp.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'gc_logs': {},
    }

    gc_log_dirs = [
        '/var/log/hadoop',
        '/var/log/hbase',
    ]
    gc_patterns = ['*gc*.log*', '*GC*.log*']
    max_bytes = 100 * 1024  # 100KB tail

    for base_dir in gc_log_dirs:
        if not os.path.isdir(base_dir):
            continue
        for root, dirs, files in os.walk(base_dir):
            for fname in files:
                fname_lower = fname.lower()
                if 'gc' in fname_lower and fname_lower.endswith(('.log', '.log.0', '.log.1', '.current')):
                    filepath = os.path.join(root, fname)
                    try:
                        size = os.path.getsize(filepath)
                        with open(filepath, 'r', errors='replace') as f:
                            if size > max_bytes:
                                f.seek(size - max_bytes)
                                f.readline()  # Skip partial line
                            content = f.read()
                        log_key = os.path.relpath(filepath, base_dir)
                        result['gc_logs'][log_key] = content
                    except (IOError, OSError) as e:
                        logger.warning("Failed to read GC log %s: %s", filepath, e)

    return result


def collect_kernel_params():
    """
    Collect kernel parameters relevant to Hadoop cluster operation.

    Returns:
        dict with keys: sysctl, thp_status, file_descriptors, timestamp.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'sysctl': {},
        'thp_status': {},
        'file_descriptors': {},
    }

    # Key sysctl parameters
    sysctl_keys = [
        'vm.swappiness',
        'vm.dirty_ratio',
        'vm.dirty_background_ratio',
        'vm.overcommit_memory',
        'net.core.somaxconn',
        'net.core.netdev_max_backlog',
        'net.core.rmem_max',
        'net.core.wmem_max',
        'net.ipv4.tcp_max_syn_backlog',
        'net.ipv4.tcp_fin_timeout',
        'fs.file-max',
    ]

    for key in sysctl_keys:
        try:
            proc = subprocess.run(
                ['sysctl', '-n', key],
                capture_output=True, text=True, timeout=5,
            )
            if proc.returncode == 0:
                result['sysctl'][key] = proc.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # THP (Transparent Huge Pages) status
    thp_paths = {
        'enabled': '/sys/kernel/mm/transparent_hugepage/enabled',
        'defrag': '/sys/kernel/mm/transparent_hugepage/defrag',
    }
    for name, path in thp_paths.items():
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    result['thp_status'][name] = f.read().strip()
        except (IOError, OSError):
            pass

    # File descriptor limits
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        result['file_descriptors']['soft_limit'] = soft
        result['file_descriptors']['hard_limit'] = hard
    except Exception:
        pass

    try:
        if os.path.exists('/proc/sys/fs/file-nr'):
            with open('/proc/sys/fs/file-nr', 'r') as f:
                parts = f.read().strip().split()
                if len(parts) >= 3:
                    result['file_descriptors']['allocated'] = int(parts[0])
                    result['file_descriptors']['free'] = int(parts[1])
                    result['file_descriptors']['max'] = int(parts[2])
    except (IOError, OSError, ValueError):
        pass

    return result


def collect_config_drift(ambari_url, cluster_name):
    """
    Detect configuration drift between Ambari desired configs and on-disk XML files.

    Args:
        ambari_url: Ambari server URL.
        cluster_name: Ambari cluster name.

    Returns:
        dict with keys: drifts (list of drift dicts), timestamp.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'drifts': [],
    }

    # Config types and their on-disk locations
    config_map = {
        'core-site': '/etc/hadoop/conf/core-site.xml',
        'hdfs-site': '/etc/hadoop/conf/hdfs-site.xml',
        'yarn-site': '/etc/hadoop/conf/yarn-site.xml',
        'mapred-site': '/etc/hadoop/conf/mapred-site.xml',
        'hive-site': '/etc/hive/conf/hive-site.xml',
        'hbase-site': '/etc/hbase/conf/hbase-site.xml',
    }

    for config_type, disk_path in config_map.items():
        if not os.path.exists(disk_path):
            continue

        # Get desired config from Ambari
        ambari_props = _get_ambari_config(ambari_url, cluster_name, config_type)
        if ambari_props is None:
            continue

        # Parse on-disk XML
        disk_props = _parse_hadoop_xml(disk_path)
        if disk_props is None:
            continue

        # Compare
        drift = _compare_configs(config_type, ambari_props, disk_props)
        if drift['differences']:
            result['drifts'].append(drift)

    return result


# === Internal helper functions ===

def _discover_component_hosts(ambari_url, cluster_name):
    """Discover component hosts from Ambari REST API."""
    hosts = {}
    components = ['NAMENODE', 'DATANODE', 'RESOURCEMANAGER', 'NODEMANAGER']

    for component in components:
        try:
            url = (
                f"{ambari_url}/api/v1/clusters/{cluster_name}"
                f"/services/HDFS/components/{component}"
                if component in ('NAMENODE', 'DATANODE')
                else f"{ambari_url}/api/v1/clusters/{cluster_name}"
                     f"/services/YARN/components/{component}"
            )
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                host_list = []
                for hc in data.get('host_components', []):
                    h = hc.get('HostRoles', {}).get('host_name', '')
                    if h:
                        host_list.append(h)
                hosts[component] = host_list
        except requests.RequestException:
            hosts[component] = []

    return hosts


def _fetch_jmx(host, ports):
    """Try to fetch JMX data from a host on given ports."""
    for port in ports:
        try:
            url = f"http://{host}:{port}/jmx"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except requests.RequestException:
            continue
    return None


def _find_bean(jmx_data, bean_name):
    """Find a JMX bean by name pattern in JMX response."""
    for bean in jmx_data.get('beans', []):
        if bean_name in bean.get('name', ''):
            return bean
    return {}


def _parse_namenode_jmx(jmx_data, host):
    """Parse NameNode JMX metrics."""
    result = {'host': host}

    fs = _find_bean(jmx_data, 'FSNamesystem')
    result['blocks_total'] = fs.get('BlocksTotal', 0)
    result['missing_blocks'] = fs.get('MissingBlocks', 0)
    result['capacity_total'] = fs.get('CapacityTotal', 0)
    result['capacity_used'] = fs.get('CapacityUsed', 0)
    result['capacity_remaining'] = fs.get('CapacityRemaining', 0)
    result['under_replicated_blocks'] = fs.get('UnderReplicatedBlocks', 0)

    jvm = _find_bean(jmx_data, 'JvmMetrics')
    result['heap_used_mb'] = jvm.get('MemHeapUsedM', 0)
    result['heap_max_mb'] = jvm.get('MemHeapMaxM', 0)
    result['gc_count'] = jvm.get('GcCount', 0)
    result['gc_time_millis'] = jvm.get('GcTimeMillis', 0)
    result['threads_runnable'] = jvm.get('ThreadsRunnable', 0)
    result['threads_blocked'] = jvm.get('ThreadsBlocked', 0)
    result['threads_waiting'] = jvm.get('ThreadsWaiting', 0)

    rpc = _find_bean(jmx_data, 'RpcActivityForPort')
    if not rpc:
        rpc = _find_bean(jmx_data, 'RpcActivity')
    result['rpc_queue_time_avg'] = rpc.get('RpcQueueTimeAvgTime', 0)
    result['rpc_num_open_connections'] = rpc.get('NumOpenConnections', 0)

    nn_info = _find_bean(jmx_data, 'NameNodeInfo')
    result['ha_state'] = nn_info.get('HAState', 'unknown')

    return result


def _parse_datanode_jmx(jmx_data, host):
    """Parse DataNode JMX metrics."""
    result = {'host': host}

    dn = _find_bean(jmx_data, 'DataNodeActivity')
    result['bytes_read'] = dn.get('BytesRead', 0)
    result['bytes_written'] = dn.get('BytesWritten', 0)
    result['blocks_read'] = dn.get('BlocksRead', 0)
    result['blocks_written'] = dn.get('BlocksWritten', 0)

    fs = _find_bean(jmx_data, 'FSDatasetState')
    result['volume_failures'] = fs.get('NumFailedVolumes', 0)
    result['capacity'] = fs.get('Capacity', 0)
    result['remaining'] = fs.get('Remaining', 0)

    return result


def _parse_resourcemanager_jmx(jmx_data, host):
    """Parse ResourceManager JMX metrics."""
    result = {'host': host}

    cluster = _find_bean(jmx_data, 'ClusterMetrics')
    result['num_active_nms'] = cluster.get('NumActiveNMs', 0)
    result['allocated_mb'] = cluster.get('AllocatedMB', 0)
    result['allocated_vcores'] = cluster.get('AllocatedVCores', 0)
    result['available_mb'] = cluster.get('AvailableMB', 0)
    result['available_vcores'] = cluster.get('AvailableVCores', 0)
    result['apps_running'] = cluster.get('AppsRunning', 0)
    result['apps_pending'] = cluster.get('AppsPending', 0)
    result['apps_submitted'] = cluster.get('AppsSubmitted', 0)

    queue = _find_bean(jmx_data, 'QueueMetrics')
    result['queue_used_capacity'] = queue.get('UsedCapacity', 0)
    result['queue_available_capacity'] = queue.get('AvailableCapacity', 0)

    return result


def _parse_nodemanager_jmx(jmx_data, host):
    """Parse NodeManager JMX metrics."""
    result = {'host': host}

    nm = _find_bean(jmx_data, 'NodeManagerMetrics')
    result['containers_launched'] = nm.get('ContainersLaunched', 0)
    result['containers_completed'] = nm.get('ContainersCompleted', 0)
    result['containers_failed'] = nm.get('ContainersFailed', 0)
    result['allocated_gb'] = nm.get('AllocatedGB', 0)
    result['allocated_vcores'] = nm.get('AllocatedVCores', 0)
    result['available_gb'] = nm.get('AvailableGB', 0)
    result['available_vcores'] = nm.get('AvailableVCores', 0)

    return result


def _get_java_pids():
    """Get Java process PIDs and names via jps."""
    pids = []
    try:
        proc = subprocess.run(
            ['jps', '-l'], capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0 and proc.stdout:
            for line in proc.stdout.strip().split('\n'):
                parts = line.strip().split(None, 1)
                if len(parts) >= 2:
                    try:
                        pid = int(parts[0])
                        name = parts[1]
                        if name != 'sun.tools.jps.Jps':
                            pids.append((pid, name))
                    except ValueError:
                        pass
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return pids


def _check_port(host, port, timeout=5):
    """Check if a TCP port is reachable."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except (socket.timeout, socket.error, OSError):
        return False


def _get_cert_info(host, port, label):
    """Get SSL certificate info for a host:port."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # Binary form fallback
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        return {
                            'host': host,
                            'port': port,
                            'label': label,
                            'status': 'certificate_present_but_not_verified',
                        }
                    return None

                not_after = cert.get('notAfter', '')
                not_before = cert.get('notBefore', '')
                subject = dict(x[0] for x in cert.get('subject', ()))
                issuer = dict(x[0] for x in cert.get('issuer', ()))

                return {
                    'host': host,
                    'port': port,
                    'label': label,
                    'subject_cn': subject.get('commonName', ''),
                    'issuer_cn': issuer.get('commonName', ''),
                    'not_before': not_before,
                    'not_after': not_after,
                    'serial_number': cert.get('serialNumber', ''),
                }
    except (ssl.SSLError, socket.error, OSError, ConnectionRefusedError) as e:
        return {
            'host': host,
            'port': port,
            'label': label,
            'error': str(e),
        }


def _get_ambari_config(ambari_url, cluster_name, config_type):
    """Get desired config properties from Ambari for a config type."""
    try:
        # First get the desired config tag
        url = f"{ambari_url}/api/v1/clusters/{cluster_name}?fields=Clusters/desired_configs/{config_type}"
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return None

        data = resp.json()
        desired = data.get('Clusters', {}).get('desired_configs', {}).get(config_type, {})
        tag = desired.get('tag', '')
        if not tag:
            return None

        # Fetch the actual config
        url = f"{ambari_url}/api/v1/clusters/{cluster_name}/configurations?type={config_type}&tag={tag}"
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return None

        data = resp.json()
        items = data.get('items', [])
        if items:
            return items[0].get('properties', {})
    except requests.RequestException:
        pass
    return None


def _parse_hadoop_xml(filepath):
    """Parse a Hadoop XML config file into a properties dict."""
    try:
        tree = ElementTree.parse(filepath)
        root = tree.getroot()
        props = {}
        for prop in root.findall('.//property'):
            name_elem = prop.find('name')
            value_elem = prop.find('value')
            if name_elem is not None and name_elem.text:
                props[name_elem.text] = value_elem.text if value_elem is not None and value_elem.text else ''
        return props
    except (ElementTree.ParseError, IOError, OSError):
        return None


def _compare_configs(config_type, ambari_props, disk_props):
    """Compare Ambari desired config with on-disk config."""
    drift = {
        'config_type': config_type,
        'differences': [],
    }

    all_keys = set(ambari_props.keys()) | set(disk_props.keys())
    for key in sorted(all_keys):
        ambari_val = ambari_props.get(key)
        disk_val = disk_props.get(key)

        if ambari_val is None:
            drift['differences'].append({
                'property': key,
                'type': 'extra_on_disk',
                'disk_value': disk_val,
            })
        elif disk_val is None:
            drift['differences'].append({
                'property': key,
                'type': 'missing_on_disk',
                'ambari_value': ambari_val,
            })
        elif ambari_val != disk_val:
            drift['differences'].append({
                'property': key,
                'type': 'value_mismatch',
                'ambari_value': ambari_val,
                'disk_value': disk_val,
            })

    return drift
