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


def collect_jmx_metrics(ambari_url, cluster_name, ssl_verify=True, auth=None):
    """
    Collect JMX metrics from Hadoop service HTTP endpoints.

    Queries NameNode, DataNode, ResourceManager, and NodeManager JMX endpoints
    to gather heap, GC, blocks, RPC, HA state, and container metrics.

    Args:
        ambari_url: Ambari server URL for host/port discovery.
        cluster_name: Ambari cluster name.
        ssl_verify: Whether to verify SSL certificates for Ambari API calls.
        auth: Optional (username, password) tuple for Ambari authentication.

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

    hosts = _discover_component_hosts(ambari_url, cluster_name, ssl_verify=ssl_verify, auth=auth)

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


def collect_ssl_certs(ambari_url, cluster_name, ssl_verify=True, auth=None):
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

    hosts = _discover_component_hosts(ambari_url, cluster_name, ssl_verify=ssl_verify, auth=auth)

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


def collect_config_drift(ambari_url, cluster_name, ssl_verify=True, auth=None):
    """
    Detect configuration drift between Ambari desired configs and on-disk XML files.

    Args:
        ambari_url: Ambari server URL.
        cluster_name: Ambari cluster name.
        ssl_verify: Whether to verify SSL certificates for Ambari API calls.
        auth: Optional (username, password) tuple for Ambari authentication.

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
        ambari_props = _get_ambari_config(ambari_url, cluster_name, config_type, ssl_verify=ssl_verify, auth=auth)
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


def collect_hbase_metrics(ambari_url, cluster_name, ssl_verify=True, auth=None):
    """
    Collect HBase Master and RegionServer metrics via JMX and Ambari REST API.

    Returns:
        dict with hmaster, regionservers, colocation, regions, tables info.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'hmaster': {},
        'regionservers': [],
        'colocation': {},
        'cluster_status': {},
    }

    hosts = _discover_service_hosts(ambari_url, cluster_name, 'HBASE',
                                     ['HBASE_MASTER', 'HBASE_REGIONSERVER'],
                                     ssl_verify=ssl_verify, auth=auth)

    # HBase Master JMX
    for host in hosts.get('HBASE_MASTER', []):
        jmx = _fetch_jmx(host, [16010])
        if jmx:
            master = _find_bean(jmx, 'Master,sub=Server')
            assign = _find_bean(jmx, 'Master,sub=AssignmentManager')
            jvm = _find_bean(jmx, 'JvmMetrics')
            result['hmaster'] = {
                'host': host,
                'num_region_servers': master.get('numRegionServers', 0),
                'num_dead_region_servers': master.get('numDeadRegionServers', 0),
                'is_active_master': master.get('isActiveMaster', False),
                'average_load': master.get('averageLoad', 0),
                'rit_count': assign.get('ritCount', 0),
                'rit_count_over_threshold': assign.get('ritCountOverThreshold', 0),
                'heap_used_mb': jvm.get('MemHeapUsedM', 0),
                'heap_max_mb': jvm.get('MemHeapMaxM', 0),
                'gc_count': jvm.get('GcCount', 0),
                'gc_time_millis': jvm.get('GcTimeMillis', 0),
            }
            break

    # RegionServer JMX
    for host in hosts.get('HBASE_REGIONSERVER', []):
        jmx = _fetch_jmx(host, [16030])
        if jmx:
            server = _find_bean(jmx, 'RegionServer,sub=Server')
            jvm = _find_bean(jmx, 'JvmMetrics')
            memory = _find_bean(jmx, 'RegionServer,sub=Memory')
            rs_info = {
                'host': host,
                'region_count': server.get('regionCount', 0),
                'store_count': server.get('storeCount', 0),
                'store_file_count': server.get('storeFileCount', 0),
                'memstore_size_mb': server.get('memStoreSize', 0) / 1024 / 1024 if server.get('memStoreSize') else 0,
                'store_file_size_mb': server.get('storeFileSize', 0) / 1024 / 1024 if server.get('storeFileSize') else 0,
                'read_request_count': server.get('readRequestCount', 0),
                'write_request_count': server.get('writeRequestCount', 0),
                'block_cache_hit_percent': server.get('blockCacheHitCachingPercent', 0),
                'slow_get_count': server.get('slowGetCount', 0),
                'slow_put_count': server.get('slowPutCount', 0),
                'compaction_queue_length': server.get('compactionQueueLength', 0),
                'flush_queue_length': server.get('flushQueueLength', 0),
                'heap_used_mb': jvm.get('MemHeapUsedM', 0),
                'heap_max_mb': jvm.get('MemHeapMaxM', 0),
                'gc_count': jvm.get('GcCount', 0),
                'gc_time_millis': jvm.get('GcTimeMillis', 0),
                'blocked_threads': jvm.get('ThreadsBlocked', 0),
            }
            if memory:
                rs_info['used_heap_mb'] = memory.get('usedHeapMB', 0)
                rs_info['max_heap_mb'] = memory.get('maxHeapMB', 0)
                rs_info['memstore_upper_limit'] = memory.get('memStoreUpperLimit', 0)
                rs_info['block_cache_size'] = memory.get('blockCacheSize', 0)
            result['regionservers'].append(rs_info)

    # Colocation check: detect RegionServers on same hosts as NameNode/ResourceManager
    nn_hosts = set()
    rm_hosts = set()
    try:
        hdfs_hosts = _discover_service_hosts(ambari_url, cluster_name, 'HDFS',
                                              ['NAMENODE'], ssl_verify=ssl_verify, auth=auth)
        nn_hosts = set(hdfs_hosts.get('NAMENODE', []))
        yarn_hosts = _discover_service_hosts(ambari_url, cluster_name, 'YARN',
                                              ['RESOURCEMANAGER'], ssl_verify=ssl_verify, auth=auth)
        rm_hosts = set(yarn_hosts.get('RESOURCEMANAGER', []))
    except Exception:
        pass

    rs_hosts = set(hosts.get('HBASE_REGIONSERVER', []))
    result['colocation'] = {
        'rs_on_namenode': list(rs_hosts & nn_hosts),
        'rs_on_resourcemanager': list(rs_hosts & rm_hosts),
        'rs_hosts': list(rs_hosts),
        'nn_hosts': list(nn_hosts),
        'rm_hosts': list(rm_hosts),
    }

    return result


def collect_impala_metrics(ambari_url, cluster_name, ssl_verify=True, auth=None):
    """
    Collect Impala daemon, catalog, and statestore metrics.

    Returns:
        dict with impalad, catalogd, statestore metrics.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'impalad': [],
        'catalogd': {},
        'statestore': {},
        'service_info': {},
    }

    hosts = _discover_service_hosts(ambari_url, cluster_name, 'IMPALA',
                                     ['IMPALAD', 'IMPALA_CATALOG', 'IMPALA_STATESTORE'],
                                     ssl_verify=ssl_verify, auth=auth)

    # Impala daemon metrics (port 25000 web UI)
    for host in hosts.get('IMPALAD', []):
        metrics = _fetch_impala_metrics(host, 25000)
        if metrics:
            result['impalad'].append({
                'host': host,
                'num_queries_running': metrics.get('impala-server.num-queries-running', 0),
                'num_queries_registered': metrics.get('impala-server.num-queries-registered', 0),
                'backend_num_queries_executing': metrics.get('impala-server.backend-num-queries-executing', 0),
                'mem_tracker_process_bytes': metrics.get('impala-server.mem-tracker.process.bytes-in-use', 0),
                'mem_tracker_process_limit': metrics.get('impala-server.mem-tracker.process.limit', 0),
                'io_mgr_bytes_read': metrics.get('impala-server.io-mgr.bytes-read', 0),
                'io_mgr_bytes_written': metrics.get('impala-server.io-mgr.bytes-written', 0),
                'catalog_num_tables': metrics.get('impala-server.catalog.num-tables', 0),
                'num_open_beeswax_sessions': metrics.get('impala-server.num-open-beeswax-sessions', 0),
                'num_open_hs2_sessions': metrics.get('impala-server.num-open-hs2-sessions', 0),
                'admission_controller_total_queued': metrics.get('admission-controller.total-queued', 0),
                'admission_controller_total_rejected': metrics.get('admission-controller.total-rejected', 0),
            })

    # Catalog daemon metrics (port 25020)
    for host in hosts.get('IMPALA_CATALOG', []):
        metrics = _fetch_impala_metrics(host, 25020)
        if metrics:
            result['catalogd'] = {
                'host': host,
                'num_tables': metrics.get('catalog.num-tables', 0),
                'num_databases': metrics.get('catalog.num-databases', 0),
                'jvm_heap_used_bytes': metrics.get('jvm.heap.current-usage-bytes', 0),
                'jvm_heap_max_bytes': metrics.get('jvm.heap.max-usage-bytes', 0),
            }
            break

    # Statestore metrics (port 25010)
    for host in hosts.get('IMPALA_STATESTORE', []):
        metrics = _fetch_impala_metrics(host, 25010)
        if metrics:
            result['statestore'] = {
                'host': host,
                'num_live_backends': metrics.get('statestore.num-live-backends', 0),
                'subscriber_heartbeat_duration_p99': metrics.get('statestore.subscriber-heartbeat-duration.p99', 0),
            }
            break

    # Count active daemons
    result['service_info'] = {
        'impalad_count': len(result['impalad']),
        'has_catalogd': bool(result['catalogd']),
        'has_statestore': bool(result['statestore']),
    }

    return result


def collect_kudu_metrics(ambari_url, cluster_name, ssl_verify=True, auth=None):
    """
    Collect Kudu Master and Tablet Server metrics.

    Returns:
        dict with kudu_master, tservers, tablet info.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'kudu_master': {},
        'tservers': [],
        'cluster_info': {},
    }

    hosts = _discover_service_hosts(ambari_url, cluster_name, 'KUDU',
                                     ['KUDU_MASTER', 'KUDU_TSERVER'],
                                     ssl_verify=ssl_verify, auth=auth)

    # Kudu Master metrics (port 8051 web UI)
    for host in hosts.get('KUDU_MASTER', []):
        metrics = _fetch_json_metrics(host, 8051, '/metrics')
        if metrics:
            parsed = _parse_kudu_master_metrics(metrics, host)
            if parsed:
                result['kudu_master'] = parsed
                break

    # Kudu Tablet Server metrics (port 8050)
    for host in hosts.get('KUDU_TSERVER', []):
        metrics = _fetch_json_metrics(host, 8050, '/metrics')
        if metrics:
            parsed = _parse_kudu_tserver_metrics(metrics, host)
            if parsed:
                result['tservers'].append(parsed)

    # Cluster info from master API
    for host in hosts.get('KUDU_MASTER', []):
        tables = _fetch_json_metrics(host, 8051, '/api/v1/tables')
        tservers = _fetch_json_metrics(host, 8051, '/api/v1/tablet-servers')
        if tables or tservers:
            result['cluster_info'] = {
                'num_tables': len(tables) if isinstance(tables, list) else 0,
                'num_tservers': len(tservers) if isinstance(tservers, list) else 0,
                'tserver_hosts': [ts.get('uuid', '') for ts in (tservers or [])] if isinstance(tservers, list) else [],
            }
            break

    return result


def collect_hive_metrics(ambari_url, cluster_name, ssl_verify=True, auth=None):
    """
    Collect Hive Server2 and Metastore metrics via JMX and Ambari REST API.

    Returns:
        dict with hiveserver2, metastore, and configuration data.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'hiveserver2': [],
        'metastore': [],
        'config': {},
        'service_info': {},
    }

    hosts = _discover_service_hosts(ambari_url, cluster_name, 'HIVE',
                                     ['HIVE_SERVER', 'HIVE_METASTORE'],
                                     ssl_verify=ssl_verify, auth=auth)

    # HiveServer2 JMX (port 10002 web UI)
    for host in hosts.get('HIVE_SERVER', []):
        jmx = _fetch_jmx(host, [10002])
        if jmx:
            hs2_jvm = _find_bean(jmx, 'JvmMetrics')
            hs2_general = _find_bean(jmx, 'HiveServer2')
            hs2_info = {
                'host': host,
                'heap_used_mb': hs2_jvm.get('MemHeapUsedM', 0),
                'heap_max_mb': hs2_jvm.get('MemHeapMaxM', 0),
                'gc_count': hs2_jvm.get('GcCount', 0),
                'gc_time_millis': hs2_jvm.get('GcTimeMillis', 0),
                'threads_runnable': hs2_jvm.get('ThreadsRunnable', 0),
                'threads_blocked': hs2_jvm.get('ThreadsBlocked', 0),
                'open_connections': hs2_general.get('open_connections', 0),
                'open_operations': hs2_general.get('open_operations', 0),
                'active_sessions': hs2_general.get('active_sessions', 0),
            }
            result['hiveserver2'].append(hs2_info)

    # Hive Metastore JMX (port 9083 doesn't have JMX by default, check via Ambari)
    for host in hosts.get('HIVE_METASTORE', []):
        result['metastore'].append({'host': host, 'status': 'discovered'})

    # Hive configuration from Ambari
    try:
        hive_cfg = _get_ambari_config(ambari_url, cluster_name, 'hive-site',
                                       ssl_verify=ssl_verify, auth=auth)
        if hive_cfg:
            result['config'] = {
                'execution_engine': hive_cfg.get('hive.execution.engine', 'mr'),
                'vectorization_enabled': hive_cfg.get('hive.vectorized.execution.enabled', 'false'),
                'tez_container_size': hive_cfg.get('hive.tez.container.size', ''),
                'tez_java_opts': hive_cfg.get('hive.tez.java.opts', ''),
                'auto_convert_join': hive_cfg.get('hive.auto.convert.join', 'true'),
                'map_join_size': hive_cfg.get('hive.auto.convert.join.noconditionaltask.size', ''),
                'merge_small_files': hive_cfg.get('hive.merge.mapfiles', 'true'),
                'compressor': hive_cfg.get('hive.exec.compress.output', 'false'),
                'orc_compression': hive_cfg.get('hive.exec.orc.default.compress', ''),
                'stats_autogather': hive_cfg.get('hive.stats.autogather', 'true'),
                'cbo_enabled': hive_cfg.get('hive.cbo.enable', 'true'),
                'fetch_task_conversion': hive_cfg.get('hive.fetch.task.conversion', 'more'),
                'dynamic_partition_mode': hive_cfg.get('hive.exec.dynamic.partition.mode', 'strict'),
                'metastore_warehouse_dir': hive_cfg.get('hive.metastore.warehouse.dir', ''),
                'acid_enabled': hive_cfg.get('hive.support.concurrency', 'false'),
                'compactor_initiator_on': hive_cfg.get('hive.compactor.initiator.on', 'false'),
            }
    except Exception as e:
        logger.warning("Failed to fetch Hive config: %s", e)

    result['service_info'] = {
        'hs2_count': len(result['hiveserver2']),
        'metastore_count': len(result['metastore']),
    }

    return result


def collect_zookeeper_metrics(ambari_url, cluster_name, ssl_verify=True, auth=None):
    """
    Collect ZooKeeper ensemble metrics via the four-letter commands (mntr/stat/conf).

    Returns:
        dict with servers, ensemble info, configuration.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'servers': [],
        'ensemble': {},
    }

    hosts = _discover_service_hosts(ambari_url, cluster_name, 'ZOOKEEPER',
                                     ['ZOOKEEPER_SERVER'],
                                     ssl_verify=ssl_verify, auth=auth)

    leaders = 0
    followers = 0
    for host in hosts.get('ZOOKEEPER_SERVER', []):
        zk_info = {'host': host}

        # Use 'mntr' four-letter word (must be whitelisted in zoo.cfg)
        mntr = _zk_command(host, 2181, 'mntr')
        if mntr:
            parsed = _parse_zk_mntr(mntr)
            zk_info.update(parsed)
            if parsed.get('zk_server_state') == 'leader':
                leaders += 1
            elif parsed.get('zk_server_state') == 'follower':
                followers += 1

        # Use 'conf' for configuration
        conf = _zk_command(host, 2181, 'conf')
        if conf:
            zk_info['config'] = _parse_zk_conf(conf)

        # Use 'stat' for connection info
        stat = _zk_command(host, 2181, 'stat')
        if stat:
            for line in stat.split('\n'):
                if 'Connections' in line or 'Outstanding' in line:
                    parts = line.strip().split(':')
                    if len(parts) == 2:
                        key = parts[0].strip().lower().replace(' ', '_')
                        val = parts[1].strip()
                        zk_info[key] = int(val) if val.isdigit() else val

        result['servers'].append(zk_info)

    result['ensemble'] = {
        'total_servers': len(hosts.get('ZOOKEEPER_SERVER', [])),
        'leaders': leaders,
        'followers': followers,
        'quorum_size': len(hosts.get('ZOOKEEPER_SERVER', [])) // 2 + 1,
        'is_odd_count': len(hosts.get('ZOOKEEPER_SERVER', [])) % 2 == 1,
    }

    return result


def collect_atlas_metrics(ambari_url, cluster_name, ssl_verify=True, auth=None):
    """
    Collect Apache Atlas metrics via REST API.

    Returns:
        dict with atlas server info, entity counts, search metrics.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'server': {},
        'entity_stats': {},
        'service_info': {},
    }

    hosts = _discover_service_hosts(ambari_url, cluster_name, 'ATLAS',
                                     ['ATLAS_SERVER'],
                                     ssl_verify=ssl_verify, auth=auth)

    for host in hosts.get('ATLAS_SERVER', []):
        # Atlas admin status (port 21000)
        try:
            resp = requests.get(f"http://{host}:21000/api/atlas/admin/status",
                                timeout=10, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                result['server'] = {
                    'host': host,
                    'status': data.get('Status', 'UNKNOWN'),
                }
        except requests.RequestException:
            result['server'] = {'host': host, 'status': 'UNREACHABLE'}

        # Atlas metrics
        try:
            resp = requests.get(f"http://{host}:21000/api/atlas/admin/metrics",
                                timeout=10, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                general = data.get('general', {})
                result['entity_stats'] = {
                    'entity_count': general.get('entityCount', 0),
                    'tag_count': general.get('tagCount', 0),
                    'type_count': general.get('typeCount', 0),
                }
                # JVM metrics from Atlas
                jvm = data.get('jvm', {})
                if jvm:
                    result['server']['heap_used_mb'] = jvm.get('heapUsed', 0) / 1024 / 1024 if jvm.get('heapUsed') else 0
                    result['server']['heap_max_mb'] = jvm.get('heapMax', 0) / 1024 / 1024 if jvm.get('heapMax') else 0
        except requests.RequestException:
            pass

        break

    result['service_info'] = {
        'atlas_count': len(hosts.get('ATLAS_SERVER', [])),
        'is_active': result.get('server', {}).get('status') == 'ACTIVE',
    }

    return result


def collect_ranger_metrics(ambari_url, cluster_name, ssl_verify=True, auth=None):
    """
    Collect Apache Ranger Admin and UserSync metrics.

    Returns:
        dict with ranger_admin, usersync info, policy counts.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'ranger_admin': {},
        'usersync': [],
        'policies': {},
        'service_info': {},
    }

    hosts = _discover_service_hosts(ambari_url, cluster_name, 'RANGER',
                                     ['RANGER_ADMIN', 'RANGER_USERSYNC'],
                                     ssl_verify=ssl_verify, auth=auth)

    # Ranger Admin (port 6080)
    for host in hosts.get('RANGER_ADMIN', []):
        try:
            # Health check
            resp = requests.get(f"http://{host}:6080/service/public/v2/api/service",
                                timeout=10, verify=False)
            if resp.status_code in (200, 401):
                result['ranger_admin'] = {
                    'host': host,
                    'status': 'ACTIVE',
                    'http_code': resp.status_code,
                }
                # Try to get service count (may need auth)
                if resp.status_code == 200:
                    try:
                        services = resp.json()
                        if isinstance(services, list):
                            result['policies']['service_count'] = len(services)
                            result['policies']['services'] = [
                                {'name': s.get('name', ''), 'type': s.get('type', '')}
                                for s in services[:20]
                            ]
                    except ValueError:
                        pass
            else:
                result['ranger_admin'] = {'host': host, 'status': 'ERROR', 'http_code': resp.status_code}
        except requests.RequestException:
            result['ranger_admin'] = {'host': host, 'status': 'UNREACHABLE'}
        break

    # UserSync hosts
    for host in hosts.get('RANGER_USERSYNC', []):
        result['usersync'].append({'host': host, 'status': 'discovered'})

    result['service_info'] = {
        'admin_count': len(hosts.get('RANGER_ADMIN', [])),
        'usersync_count': len(hosts.get('RANGER_USERSYNC', [])),
        'is_active': result.get('ranger_admin', {}).get('status') == 'ACTIVE',
    }

    return result


def collect_nifi_metrics(ambari_url, cluster_name, ssl_verify=True, auth=None):
    """
    Collect Apache NiFi cluster and flow metrics via REST API.

    Returns:
        dict with cluster info, system diagnostics, flow status.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'cluster': {},
        'system_diagnostics': {},
        'flow_status': {},
        'service_info': {},
    }

    hosts = _discover_service_hosts(ambari_url, cluster_name, 'NIFI',
                                     ['NIFI_MASTER'],
                                     ssl_verify=ssl_verify, auth=auth)

    for host in hosts.get('NIFI_MASTER', []):
        base_url = f"http://{host}:8080/nifi-api"

        # Cluster info
        try:
            resp = requests.get(f"{base_url}/controller/cluster", timeout=10, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                cluster = data.get('cluster', {})
                nodes = cluster.get('nodes', [])
                result['cluster'] = {
                    'node_count': len(nodes),
                    'connected_nodes': sum(1 for n in nodes if n.get('status') == 'CONNECTED'),
                    'disconnected_nodes': sum(1 for n in nodes if n.get('status') != 'CONNECTED'),
                    'nodes': [{
                        'address': n.get('address', ''),
                        'status': n.get('status', ''),
                        'queued': n.get('queued', ''),
                    } for n in nodes],
                }
        except requests.RequestException:
            pass

        # System diagnostics
        try:
            resp = requests.get(f"{base_url}/system-diagnostics", timeout=10, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                sd = data.get('systemDiagnostics', {}).get('aggregateSnapshot', {})
                result['system_diagnostics'] = {
                    'total_threads': sd.get('totalThreads', 0),
                    'daemon_threads': sd.get('daemonThreads', 0),
                    'max_heap_bytes': sd.get('maxHeap', 0),
                    'used_heap_bytes': sd.get('usedHeap', 0),
                    'heap_utilization': sd.get('heapUtilization', ''),
                    'available_processors': sd.get('availableProcessors', 0),
                    'processor_load': sd.get('processorLoadAverage', 0),
                    'total_content_repo_bytes': sd.get('contentRepositoryStorageUsage', [{}])[0].get('totalSpace', 0) if sd.get('contentRepositoryStorageUsage') else 0,
                    'free_content_repo_bytes': sd.get('contentRepositoryStorageUsage', [{}])[0].get('freeSpace', 0) if sd.get('contentRepositoryStorageUsage') else 0,
                    'total_flowfile_repo_bytes': sd.get('flowFileRepositoryStorageUsage', {}).get('totalSpace', 0),
                    'free_flowfile_repo_bytes': sd.get('flowFileRepositoryStorageUsage', {}).get('freeSpace', 0),
                }
        except requests.RequestException:
            pass

        # Flow status (root process group)
        try:
            resp = requests.get(f"{base_url}/flow/status", timeout=10, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                cs = data.get('controllerStatus', {})
                result['flow_status'] = {
                    'active_threads': cs.get('activeThreadCount', 0),
                    'queued_count': cs.get('flowFilesQueued', 0),
                    'queued_bytes': cs.get('bytesQueued', 0),
                    'running_count': cs.get('runningCount', 0),
                    'stopped_count': cs.get('stoppedCount', 0),
                    'invalid_count': cs.get('invalidCount', 0),
                    'disabled_count': cs.get('disabledCount', 0),
                    'active_remote_port_count': cs.get('activeRemotePortCount', 0),
                }
        except requests.RequestException:
            pass

        break

    result['service_info'] = {
        'nifi_node_count': len(hosts.get('NIFI_MASTER', [])),
        'is_clustered': result.get('cluster', {}).get('node_count', 0) > 1,
    }

    return result


def collect_spark_metrics(ambari_url, cluster_name, ssl_verify=True, auth=None):
    """
    Collect Spark History Server metrics and configuration.

    Returns:
        dict with history_server info, applications, configuration.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'history_server': {},
        'config': {},
        'service_info': {},
    }

    hosts = _discover_service_hosts(ambari_url, cluster_name, 'SPARK2',
                                     ['SPARK2_JOBHISTORYSERVER'],
                                     ssl_verify=ssl_verify, auth=auth)
    if not hosts.get('SPARK2_JOBHISTORYSERVER'):
        hosts = _discover_service_hosts(ambari_url, cluster_name, 'SPARK',
                                         ['SPARK_JOBHISTORYSERVER'],
                                         ssl_verify=ssl_verify, auth=auth)

    hs_hosts = hosts.get('SPARK2_JOBHISTORYSERVER', hosts.get('SPARK_JOBHISTORYSERVER', []))

    for host in hs_hosts:
        try:
            resp = requests.get(f"http://{host}:18081/api/v1/applications?limit=5",
                                timeout=10)
            if resp.status_code == 200:
                apps = resp.json()
                result['history_server'] = {
                    'host': host,
                    'status': 'ACTIVE',
                    'recent_apps_count': len(apps),
                }
        except requests.RequestException:
            result['history_server'] = {'host': host, 'status': 'UNREACHABLE'}
        break

    # Spark defaults from Ambari
    for cfg_type in ('spark2-defaults', 'spark-defaults'):
        spark_cfg = _get_ambari_config(ambari_url, cluster_name, cfg_type,
                                        ssl_verify=ssl_verify, auth=auth)
        if spark_cfg:
            result['config'] = {
                'dynamic_allocation': spark_cfg.get('spark.dynamicAllocation.enabled', 'false'),
                'serializer': spark_cfg.get('spark.serializer', ''),
                'executor_memory': spark_cfg.get('spark.executor.memory', '1g'),
                'driver_memory': spark_cfg.get('spark.driver.memory', '1g'),
                'executor_cores': spark_cfg.get('spark.executor.cores', '1'),
                'shuffle_partitions': spark_cfg.get('spark.sql.shuffle.partitions', '200'),
                'event_log_enabled': spark_cfg.get('spark.eventLog.enabled', 'true'),
                'event_log_dir': spark_cfg.get('spark.eventLog.dir', ''),
                'speculation': spark_cfg.get('spark.speculation', 'false'),
                'adaptive_enabled': spark_cfg.get('spark.sql.adaptive.enabled', 'false'),
            }
            break

    result['service_info'] = {
        'history_server_count': len(hs_hosts),
    }
    return result


def collect_oozie_metrics(ambari_url, cluster_name, ssl_verify=True, auth=None):
    """
    Collect Oozie server metrics and configuration.

    Returns:
        dict with server status, instrumentation, configuration.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'server': {},
        'instrumentation': {},
        'config': {},
        'service_info': {},
    }

    hosts = _discover_service_hosts(ambari_url, cluster_name, 'OOZIE',
                                     ['OOZIE_SERVER'],
                                     ssl_verify=ssl_verify, auth=auth)

    for host in hosts.get('OOZIE_SERVER', []):
        # Oozie status
        try:
            resp = requests.get(f"http://{host}:11000/oozie/v2/admin/status", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                result['server'] = {
                    'host': host,
                    'system_mode': data.get('systemMode', 'UNKNOWN'),
                }
        except requests.RequestException:
            result['server'] = {'host': host, 'system_mode': 'UNREACHABLE'}

        # Oozie instrumentation (metrics)
        try:
            resp = requests.get(f"http://{host}:11000/oozie/v2/admin/instrumentation", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                counters = {}
                for group in data.get('counters', []):
                    group_name = group.get('group', '')
                    for item in group.get('data', []):
                        counters[f"{group_name}.{item.get('name', '')}"] = item.get('value', 0)
                result['instrumentation'] = counters
        except requests.RequestException:
            pass
        break

    # Oozie config from Ambari
    oozie_cfg = _get_ambari_config(ambari_url, cluster_name, 'oozie-site',
                                    ssl_verify=ssl_verify, auth=auth)
    if oozie_cfg:
        result['config'] = {
            'base_url': oozie_cfg.get('oozie.base.url', ''),
            'sla_enabled': oozie_cfg.get('oozie.service.SLAService.status.store.class', '') != '',
            'shared_lib_path': oozie_cfg.get('oozie.service.WorkflowAppService.system.libpath', ''),
        }

    result['service_info'] = {
        'oozie_count': len(hosts.get('OOZIE_SERVER', [])),
    }
    return result


def collect_solr_metrics(ambari_url, cluster_name, ssl_verify=True, auth=None):
    """
    Collect Solr/Infra Solr cluster metrics.

    Returns:
        dict with cluster status, collections, JVM metrics.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'cluster_status': {},
        'collections': [],
        'jvm': {},
        'service_info': {},
    }

    # Try INFRA_SOLR first (Ambari Infra), then standalone SOLR
    for service, component in [('AMBARI_INFRA_SOLR', 'INFRA_SOLR'),
                                ('SOLR', 'SOLR_SERVER')]:
        hosts = _discover_service_hosts(ambari_url, cluster_name, service,
                                         [component], ssl_verify=ssl_verify, auth=auth)
        if hosts.get(component):
            break

    solr_hosts = hosts.get(component, [])

    for host in solr_hosts:
        port = 8886 if 'INFRA' in component else 8983

        # Cluster status
        try:
            resp = requests.get(f"http://{host}:{port}/solr/admin/collections?action=CLUSTERSTATUS",
                                timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                cluster = data.get('cluster', {})
                collections = cluster.get('collections', {})
                live_nodes = cluster.get('live_nodes', [])
                result['cluster_status'] = {
                    'live_nodes': len(live_nodes),
                    'collections_count': len(collections),
                }
                for col_name, col_data in list(collections.items())[:20]:
                    shards = col_data.get('shards', {})
                    result['collections'].append({
                        'name': col_name,
                        'num_shards': len(shards),
                        'replication_factor': col_data.get('replicationFactor', 1),
                        'config_name': col_data.get('configName', ''),
                    })
        except requests.RequestException:
            pass

        # JVM metrics
        jmx = _fetch_jmx(host, [port])
        if jmx:
            jvm = _find_bean(jmx, 'JvmMetrics')
            if not jvm:
                jvm = _find_bean(jmx, 'java.lang:type=Memory')
            result['jvm'] = {
                'host': host,
                'heap_used_mb': jvm.get('MemHeapUsedM', 0) if jvm else 0,
                'heap_max_mb': jvm.get('MemHeapMaxM', 0) if jvm else 0,
            }
        break

    result['service_info'] = {
        'solr_node_count': len(solr_hosts),
    }
    return result


def collect_kafka_metrics(ambari_url, cluster_name, ssl_verify=True, auth=None):
    """
    Collect Kafka broker metrics via JMX.

    Returns:
        dict with brokers, topic info, consumer lag data.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'brokers': [],
        'cluster_info': {},
    }

    hosts = _discover_service_hosts(ambari_url, cluster_name, 'KAFKA',
                                     ['KAFKA_BROKER'],
                                     ssl_verify=ssl_verify, auth=auth)

    for host in hosts.get('KAFKA_BROKER', []):
        jmx = _fetch_jmx(host, [9999])  # Kafka JMX port (configurable)
        broker_info = {'host': host}

        if jmx:
            # Server / BrokerTopicMetrics
            btm = _find_bean(jmx, 'BrokerTopicMetrics')
            broker_info['messages_in_per_sec'] = btm.get('MessagesInPerSec', {}).get('OneMinuteRate', 0) if isinstance(btm.get('MessagesInPerSec'), dict) else btm.get('MessagesInPerSec', 0)
            broker_info['bytes_in_per_sec'] = btm.get('BytesInPerSec', {}).get('OneMinuteRate', 0) if isinstance(btm.get('BytesInPerSec'), dict) else btm.get('BytesInPerSec', 0)
            broker_info['bytes_out_per_sec'] = btm.get('BytesOutPerSec', {}).get('OneMinuteRate', 0) if isinstance(btm.get('BytesOutPerSec'), dict) else btm.get('BytesOutPerSec', 0)

            # ReplicaManager
            rm = _find_bean(jmx, 'ReplicaManager')
            broker_info['partition_count'] = rm.get('PartitionCount', 0)
            broker_info['under_replicated_partitions'] = rm.get('UnderReplicatedPartitions', 0)
            broker_info['offline_partitions_count'] = rm.get('OfflinePartitionsCount', 0) if rm.get('OfflinePartitionsCount') is not None else 0
            broker_info['leader_count'] = rm.get('LeaderCount', 0)

            # Controller
            ctrl = _find_bean(jmx, 'KafkaController')
            broker_info['active_controller_count'] = ctrl.get('ActiveControllerCount', 0)

            # Request metrics
            req = _find_bean(jmx, 'RequestMetrics')
            broker_info['request_queue_size'] = req.get('RequestQueueSize', 0) if req else 0

            # Log / LogFlush
            log_flush = _find_bean(jmx, 'LogFlushStats')
            broker_info['log_flush_rate'] = log_flush.get('LogFlushRateAndTimeMs', {}).get('OneMinuteRate', 0) if isinstance(log_flush.get('LogFlushRateAndTimeMs'), dict) else 0

            # JVM
            jvm = _find_bean(jmx, 'JvmMetrics')
            if not jvm:
                jvm = _find_bean(jmx, 'java.lang:type=Memory')
            broker_info['heap_used_mb'] = jvm.get('MemHeapUsedM', 0) if jvm else 0
            broker_info['heap_max_mb'] = jvm.get('MemHeapMaxM', 0) if jvm else 0

        result['brokers'].append(broker_info)

    total_brokers = len(hosts.get('KAFKA_BROKER', []))
    result['cluster_info'] = {
        'total_brokers': total_brokers,
        'min_isr_brokers': max(1, total_brokers - 1),
    }

    return result


# === Internal helper functions ===

def _discover_component_hosts(ambari_url, cluster_name, ssl_verify=True, auth=None):
    """Discover HDFS/YARN component hosts from Ambari REST API."""
    hosts = {}
    components = ['NAMENODE', 'DATANODE', 'RESOURCEMANAGER', 'NODEMANAGER']

    for component in components:
        try:
            service = 'HDFS' if component in ('NAMENODE', 'DATANODE') else 'YARN'
            url = f"{ambari_url}/api/v1/clusters/{cluster_name}/services/{service}/components/{component}"
            resp = requests.get(url, timeout=10, verify=ssl_verify, auth=auth)
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


def _discover_service_hosts(ambari_url, cluster_name, service_name, component_names,
                             ssl_verify=True, auth=None):
    """Discover hosts for any Ambari service and its components."""
    hosts = {}
    for component in component_names:
        try:
            url = (f"{ambari_url}/api/v1/clusters/{cluster_name}"
                   f"/services/{service_name}/components/{component}")
            resp = requests.get(url, timeout=10, verify=ssl_verify, auth=auth)
            if resp.status_code == 200:
                data = resp.json()
                host_list = []
                for hc in data.get('host_components', []):
                    h = hc.get('HostRoles', {}).get('host_name', '')
                    if h:
                        host_list.append(h)
                hosts[component] = host_list
            else:
                hosts[component] = []
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


def _get_ambari_config(ambari_url, cluster_name, config_type, ssl_verify=True, auth=None):
    """Get desired config properties from Ambari for a config type."""
    try:
        # First get the desired config tag
        url = f"{ambari_url}/api/v1/clusters/{cluster_name}?fields=Clusters/desired_configs/{config_type}"
        resp = requests.get(url, timeout=10, verify=ssl_verify, auth=auth)
        if resp.status_code != 200:
            return None

        data = resp.json()
        desired = data.get('Clusters', {}).get('desired_configs', {}).get(config_type, {})
        tag = desired.get('tag', '')
        if not tag:
            return None

        # Fetch the actual config
        url = f"{ambari_url}/api/v1/clusters/{cluster_name}/configurations?type={config_type}&tag={tag}"
        resp = requests.get(url, timeout=10, verify=ssl_verify, auth=auth)
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


def _fetch_impala_metrics(host, port):
    """Fetch metrics from Impala web UI /metrics endpoint."""
    try:
        url = f"http://{host}:{port}/metrics?json"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            # Impala returns {"__common__": {...}, "metric_group": {"metrics": [...]}}
            flat = {}
            for group_name, group_data in data.items():
                if isinstance(group_data, dict):
                    for metric in group_data.get('metrics', []):
                        if isinstance(metric, dict) and 'name' in metric:
                            flat[metric['name']] = metric.get('value', 0)
            return flat
    except (requests.RequestException, ValueError):
        pass
    return None


def _fetch_json_metrics(host, port, path):
    """Fetch JSON metrics from a REST endpoint."""
    try:
        url = f"http://{host}:{port}{path}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except (requests.RequestException, ValueError):
        pass
    return None


def _parse_kudu_master_metrics(metrics_data, host):
    """Parse Kudu master /metrics JSON response."""
    result = {'host': host}
    if not isinstance(metrics_data, list):
        return result
    for entity in metrics_data:
        if not isinstance(entity, dict):
            continue
        entity_type = entity.get('type', '')
        for metric in entity.get('metrics', []):
            name = metric.get('name', '')
            value = metric.get('value', 0)
            if entity_type == 'server' and name == 'num_raft_leaders':
                result['num_raft_leaders'] = value
            elif name == 'cluster_replica_skew':
                result['cluster_replica_skew'] = value
            elif name == 'num_tablet_servers_live':
                result['num_tservers_live'] = value
            elif name == 'num_tablet_servers_dead':
                result['num_tservers_dead'] = value
    return result


def _parse_kudu_tserver_metrics(metrics_data, host):
    """Parse Kudu tablet server /metrics JSON response."""
    result = {'host': host}
    if not isinstance(metrics_data, list):
        return result
    for entity in metrics_data:
        if not isinstance(entity, dict):
            continue
        for metric in entity.get('metrics', []):
            name = metric.get('name', '')
            value = metric.get('value', 0)
            if name == 'tablets_num_running':
                result['tablets_running'] = value
            elif name == 'tablets_num_bootstrapping':
                result['tablets_bootstrapping'] = value
            elif name == 'tablets_num_failed':
                result['tablets_failed'] = value
            elif name == 'block_cache_hits_caching':
                result['block_cache_hits'] = value
            elif name == 'block_cache_misses_caching':
                result['block_cache_misses'] = value
            elif name == 'generic_current_allocated_bytes':
                result['memory_allocated_bytes'] = value
            elif name == 'data_dirs_full':
                result['data_dirs_full'] = value
    return result


def _zk_command(host, port, command, timeout=5):
    """Send a four-letter command to ZooKeeper and return the response."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(command.encode())
        response = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        s.close()
        return response.decode('utf-8', errors='replace')
    except (socket.timeout, socket.error, OSError):
        return None


def _parse_zk_mntr(output):
    """Parse ZooKeeper 'mntr' command output into a dict."""
    result = {}
    for line in output.strip().split('\n'):
        parts = line.split('\t')
        if len(parts) == 2:
            key = parts[0].strip()
            val = parts[1].strip()
            try:
                val = int(val)
            except ValueError:
                try:
                    val = float(val)
                except ValueError:
                    pass
            result[key] = val
    return result


def _parse_zk_conf(output):
    """Parse ZooKeeper 'conf' command output into a dict."""
    result = {}
    for line in output.strip().split('\n'):
        if '=' in line:
            key, _, val = line.partition('=')
            result[key.strip()] = val.strip()
    return result
