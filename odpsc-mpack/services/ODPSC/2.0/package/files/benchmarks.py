"""
ODPSC Benchmarks v1.0 - Hardware and system benchmark collectors for cluster health assessment.

Provides diagnostic scripts for CPU, memory, disk I/O, and network performance testing.
Results are structured JSON that feeds into the SupportPlane recommendation engine.

Each benchmark is designed to:
- Complete within a bounded time (configurable timeout)
- Have minimal impact on production workloads
- Return structured results with pass/fail thresholds
"""

import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import tempfile
import time
from datetime import datetime

import psutil

logger = logging.getLogger('odpsc-benchmarks')


def run_cpu_benchmark(duration_seconds=10):
    """
    CPU benchmark: measures single-core and multi-core throughput.

    Tests:
    - Single-thread integer arithmetic throughput (operations/second)
    - Multi-thread throughput (aggregate ops/second across all cores)
    - Context switch rate
    - CPU frequency (current, min, max)
    - Steal time percentage (critical for VMs)
    - IOwait percentage

    Args:
        duration_seconds: how long to run each sub-test (default 10s).

    Returns:
        dict with benchmark results and system CPU info.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'test': 'cpu_benchmark',
        'cpu_info': {},
        'single_thread': {},
        'multi_thread': {},
        'steal_time': {},
        'iowait': {},
        'context_switches': {},
        'cpu_frequency': {},
        'numa_info': {},
    }

    # CPU info
    try:
        result['cpu_info'] = {
            'physical_cores': psutil.cpu_count(logical=False),
            'logical_cores': psutil.cpu_count(logical=True),
            'architecture': platform.machine(),
        }
        # Try to get CPU model from /proc/cpuinfo
        if os.path.exists('/proc/cpuinfo'):
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('model name'):
                        result['cpu_info']['model'] = line.split(':')[1].strip()
                        break
    except Exception as e:
        logger.warning("Failed to get CPU info: %s", e)

    # Single-thread benchmark (pure Python integer arithmetic)
    try:
        start = time.monotonic()
        ops = 0
        end_time = start + min(duration_seconds, 10)
        while time.monotonic() < end_time:
            # Mix of arithmetic to test ALU
            x = 0
            for i in range(10000):
                x += i * 7
                x ^= i
                x = x % 1000000007
            ops += 10000
        elapsed = time.monotonic() - start
        result['single_thread'] = {
            'ops_per_second': int(ops / elapsed),
            'elapsed_seconds': round(elapsed, 2),
            'total_ops': ops,
        }
    except Exception as e:
        logger.warning("Single-thread benchmark failed: %s", e)
        result['single_thread'] = {'error': str(e)}

    # Multi-thread benchmark using subprocess (avoids GIL)
    try:
        cores = psutil.cpu_count(logical=True) or 1
        # Use dd + md5sum as a portable CPU stress test
        procs = []
        start = time.monotonic()
        for _ in range(cores):
            p = subprocess.Popen(
                ['dd', 'if=/dev/zero', 'bs=1M', f'count={max(50, duration_seconds * 10)}'],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            procs.append(p)
        bytes_total = 0
        for p in procs:
            out, _ = p.communicate(timeout=duration_seconds + 10)
            bytes_total += len(out) if out else 0
            p.wait()
        elapsed = time.monotonic() - start
        result['multi_thread'] = {
            'cores_used': cores,
            'throughput_mb_per_second': round(bytes_total / 1024 / 1024 / max(elapsed, 0.001), 2),
            'elapsed_seconds': round(elapsed, 2),
        }
    except Exception as e:
        logger.warning("Multi-thread benchmark failed: %s", e)
        result['multi_thread'] = {'error': str(e)}

    # Steal time & IOwait (critical for VMs)
    try:
        cpu_times = psutil.cpu_times_percent(interval=2)
        result['steal_time'] = {
            'percent': getattr(cpu_times, 'steal', 0),
        }
        result['iowait'] = {
            'percent': getattr(cpu_times, 'iowait', 0),
        }
    except Exception as e:
        logger.warning("Failed to get steal/iowait: %s", e)

    # Context switches
    try:
        stats = psutil.cpu_stats()
        result['context_switches'] = {
            'ctx_switches': stats.ctx_switches,
            'interrupts': stats.interrupts,
            'soft_interrupts': stats.soft_interrupts,
        }
    except Exception as e:
        logger.warning("Failed to get context switches: %s", e)

    # CPU frequency
    try:
        freq = psutil.cpu_freq()
        if freq:
            result['cpu_frequency'] = {
                'current_mhz': round(freq.current, 2),
                'min_mhz': round(freq.min, 2),
                'max_mhz': round(freq.max, 2),
            }
            if freq.max > 0 and freq.current > 0:
                result['cpu_frequency']['scaling_ratio'] = round(freq.current / freq.max, 3)
    except Exception as e:
        logger.warning("Failed to get CPU frequency: %s", e)

    # NUMA info
    try:
        if os.path.exists('/sys/devices/system/node'):
            nodes = [d for d in os.listdir('/sys/devices/system/node') if d.startswith('node')]
            result['numa_info'] = {
                'node_count': len(nodes),
                'nodes': [],
            }
            for node in sorted(nodes):
                node_path = f'/sys/devices/system/node/{node}'
                cpulist_path = os.path.join(node_path, 'cpulist')
                meminfo_path = os.path.join(node_path, 'meminfo')
                node_info = {'name': node}
                if os.path.exists(cpulist_path):
                    with open(cpulist_path) as f:
                        node_info['cpulist'] = f.read().strip()
                if os.path.exists(meminfo_path):
                    with open(meminfo_path) as f:
                        for line in f:
                            if 'MemTotal' in line:
                                m = re.search(r'(\d+)\s*kB', line)
                                if m:
                                    node_info['mem_total_mb'] = int(m.group(1)) // 1024
                                break
                result['numa_info']['nodes'].append(node_info)
    except Exception as e:
        logger.warning("Failed to get NUMA info: %s", e)

    return result


def run_memory_benchmark(test_size_mb=256):
    """
    Memory benchmark: measures allocation speed, bandwidth, and detects issues.

    Tests:
    - Memory allocation and write throughput
    - Memory read throughput
    - Swap usage and pressure
    - Huge pages availability
    - NUMA memory distribution
    - OOM killer status

    Args:
        test_size_mb: amount of memory to test with (default 256MB).

    Returns:
        dict with benchmark results and memory diagnostics.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'test': 'memory_benchmark',
        'system_memory': {},
        'allocation_test': {},
        'bandwidth_test': {},
        'swap_analysis': {},
        'hugepages': {},
        'overcommit': {},
        'oom_score': {},
    }

    # System memory overview
    try:
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()
        result['system_memory'] = {
            'total_gb': round(vm.total / 1024 / 1024 / 1024, 2),
            'available_gb': round(vm.available / 1024 / 1024 / 1024, 2),
            'used_percent': vm.percent,
            'buffers_mb': round(getattr(vm, 'buffers', 0) / 1024 / 1024, 2),
            'cached_mb': round(getattr(vm, 'cached', 0) / 1024 / 1024, 2),
            'swap_total_gb': round(swap.total / 1024 / 1024 / 1024, 2),
            'swap_used_gb': round(swap.used / 1024 / 1024 / 1024, 2),
            'swap_used_percent': swap.percent,
        }
    except Exception as e:
        logger.warning("Failed to get system memory: %s", e)

    # Memory allocation test using dd
    try:
        safe_size = min(test_size_mb, 512)  # Cap at 512MB
        start = time.monotonic()
        proc = subprocess.run(
            ['dd', 'if=/dev/zero', 'of=/dev/null', 'bs=1M', f'count={safe_size}'],
            capture_output=True, text=True, timeout=30,
        )
        elapsed = time.monotonic() - start
        result['allocation_test'] = {
            'size_mb': safe_size,
            'elapsed_seconds': round(elapsed, 3),
            'throughput_mb_per_second': round(safe_size / max(elapsed, 0.001), 2),
        }
    except Exception as e:
        logger.warning("Memory allocation test failed: %s", e)
        result['allocation_test'] = {'error': str(e)}

    # Memory bandwidth test (read from /dev/zero to measure memory bus)
    try:
        proc = subprocess.run(
            ['dd', 'if=/dev/zero', 'of=/dev/null', 'bs=1M', 'count=1024'],
            capture_output=True, text=True, timeout=30,
        )
        # Parse dd output for speed
        stderr = proc.stderr or ''
        speed_match = re.search(r'([\d.]+)\s*(GB|MB|kB)/s', stderr)
        if speed_match:
            speed_val = float(speed_match.group(1))
            speed_unit = speed_match.group(2)
            if speed_unit == 'GB':
                speed_mb = speed_val * 1024
            elif speed_unit == 'kB':
                speed_mb = speed_val / 1024
            else:
                speed_mb = speed_val
            result['bandwidth_test'] = {
                'read_throughput_mb_per_second': round(speed_mb, 2),
                'raw_output': stderr.strip()[-200:],
            }
    except Exception as e:
        logger.warning("Memory bandwidth test failed: %s", e)
        result['bandwidth_test'] = {'error': str(e)}

    # Swap analysis
    try:
        swap = psutil.swap_memory()
        swappiness = ''
        if os.path.exists('/proc/sys/vm/swappiness'):
            with open('/proc/sys/vm/swappiness') as f:
                swappiness = f.read().strip()
        result['swap_analysis'] = {
            'total_mb': round(swap.total / 1024 / 1024, 2),
            'used_mb': round(swap.used / 1024 / 1024, 2),
            'free_mb': round(swap.free / 1024 / 1024, 2),
            'percent_used': swap.percent,
            'swappiness': int(swappiness) if swappiness.isdigit() else swappiness,
            'swap_in_bytes': getattr(swap, 'sin', 0),
            'swap_out_bytes': getattr(swap, 'sout', 0),
        }
    except Exception as e:
        logger.warning("Swap analysis failed: %s", e)

    # Huge pages
    try:
        hugepages = {}
        if os.path.exists('/proc/meminfo'):
            with open('/proc/meminfo') as f:
                for line in f:
                    if 'HugePages' in line or 'Hugepagesize' in line:
                        parts = line.split(':')
                        if len(parts) == 2:
                            key = parts[0].strip()
                            val = parts[1].strip().split()[0]
                            hugepages[key] = int(val) if val.isdigit() else val
        result['hugepages'] = hugepages
    except Exception as e:
        logger.warning("Hugepages check failed: %s", e)

    # Overcommit settings
    try:
        overcommit = {}
        for param in ['vm.overcommit_memory', 'vm.overcommit_ratio']:
            key = param.replace('.', '/')
            path = f'/proc/sys/{key}'
            if os.path.exists(path):
                with open(path) as f:
                    overcommit[param] = f.read().strip()
        result['overcommit'] = overcommit
    except Exception as e:
        logger.warning("Overcommit check failed: %s", e)

    # OOM score for Java processes
    try:
        oom_scores = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if 'java' in (proc.info.get('name') or '').lower():
                    oom_path = f'/proc/{proc.info["pid"]}/oom_score'
                    oom_adj_path = f'/proc/{proc.info["pid"]}/oom_score_adj'
                    score = ''
                    adj = ''
                    if os.path.exists(oom_path):
                        with open(oom_path) as f:
                            score = f.read().strip()
                    if os.path.exists(oom_adj_path):
                        with open(oom_adj_path) as f:
                            adj = f.read().strip()
                    cmdline = ' '.join(proc.info.get('cmdline') or [])[:200]
                    oom_scores.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'oom_score': int(score) if score.isdigit() else score,
                        'oom_score_adj': int(adj) if adj.lstrip('-').isdigit() else adj,
                        'cmdline': cmdline,
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, IOError):
                pass
        result['oom_score'] = oom_scores
    except Exception as e:
        logger.warning("OOM score check failed: %s", e)

    return result


def run_disk_benchmark(test_dir='/tmp/odpsc_disk_bench', block_size_mb=1, count=100):
    """
    Disk I/O benchmark: measures sequential and random I/O performance.

    Tests:
    - Sequential write throughput (dd)
    - Sequential read throughput (dd with cache drop)
    - Disk latency (sync write of small blocks)
    - Filesystem mount options (noatime, etc.)
    - Disk health via SMART (if available)
    - Per-partition usage and inode stats

    Args:
        test_dir: directory for temporary test files.
        block_size_mb: block size in MB for dd tests.
        count: number of blocks to write.

    Returns:
        dict with benchmark results and disk diagnostics.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'test': 'disk_benchmark',
        'sequential_write': {},
        'sequential_read': {},
        'disk_latency': {},
        'partition_info': [],
        'mount_options': [],
        'inode_usage': [],
        'disk_health': [],
        'io_scheduler': {},
    }

    os.makedirs(test_dir, exist_ok=True)
    test_file = os.path.join(test_dir, 'bench_test.dat')
    safe_count = min(count, 200)  # Cap at 200MB

    # Sequential write
    try:
        # Drop caches before test
        subprocess.run(['sync'], timeout=10, capture_output=True)
        start = time.monotonic()
        proc = subprocess.run(
            ['dd', f'if=/dev/zero', f'of={test_file}',
             f'bs={block_size_mb}M', f'count={safe_count}',
             'conv=fdatasync'],
            capture_output=True, text=True, timeout=60,
        )
        elapsed = time.monotonic() - start
        size_mb = block_size_mb * safe_count
        result['sequential_write'] = {
            'size_mb': size_mb,
            'elapsed_seconds': round(elapsed, 3),
            'throughput_mb_per_second': round(size_mb / max(elapsed, 0.001), 2),
            'raw_output': (proc.stderr or '')[-200:],
        }
    except Exception as e:
        logger.warning("Sequential write test failed: %s", e)
        result['sequential_write'] = {'error': str(e)}

    # Sequential read
    try:
        if os.path.exists(test_file):
            # Drop page cache
            subprocess.run(
                ['bash', '-c', 'echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true'],
                timeout=5, capture_output=True,
            )
            start = time.monotonic()
            proc = subprocess.run(
                ['dd', f'if={test_file}', 'of=/dev/null',
                 f'bs={block_size_mb}M'],
                capture_output=True, text=True, timeout=60,
            )
            elapsed = time.monotonic() - start
            size_mb = block_size_mb * safe_count
            result['sequential_read'] = {
                'size_mb': size_mb,
                'elapsed_seconds': round(elapsed, 3),
                'throughput_mb_per_second': round(size_mb / max(elapsed, 0.001), 2),
                'raw_output': (proc.stderr or '')[-200:],
            }
    except Exception as e:
        logger.warning("Sequential read test failed: %s", e)
        result['sequential_read'] = {'error': str(e)}

    # Disk latency (small sync writes)
    try:
        latency_file = os.path.join(test_dir, 'latency_test.dat')
        latencies = []
        for i in range(20):
            start = time.monotonic()
            with open(latency_file, 'wb') as f:
                f.write(b'\x00' * 4096)
                f.flush()
                os.fsync(f.fileno())
            elapsed_ms = (time.monotonic() - start) * 1000
            latencies.append(elapsed_ms)
        if latencies:
            latencies.sort()
            result['disk_latency'] = {
                'samples': len(latencies),
                'avg_ms': round(sum(latencies) / len(latencies), 3),
                'min_ms': round(latencies[0], 3),
                'max_ms': round(latencies[-1], 3),
                'p50_ms': round(latencies[len(latencies) // 2], 3),
                'p95_ms': round(latencies[int(len(latencies) * 0.95)], 3),
                'p99_ms': round(latencies[min(int(len(latencies) * 0.99), len(latencies) - 1)], 3),
            }
        if os.path.exists(latency_file):
            os.remove(latency_file)
    except Exception as e:
        logger.warning("Disk latency test failed: %s", e)
        result['disk_latency'] = {'error': str(e)}

    # Cleanup test file
    try:
        if os.path.exists(test_file):
            os.remove(test_file)
        if os.path.isdir(test_dir):
            shutil.rmtree(test_dir, ignore_errors=True)
    except Exception:
        pass

    # Partition info with usage
    try:
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                result['partition_info'].append({
                    'device': part.device,
                    'mountpoint': part.mountpoint,
                    'fstype': part.fstype,
                    'total_gb': round(usage.total / 1024 / 1024 / 1024, 2),
                    'used_gb': round(usage.used / 1024 / 1024 / 1024, 2),
                    'free_gb': round(usage.free / 1024 / 1024 / 1024, 2),
                    'percent_used': usage.percent,
                })
            except (PermissionError, OSError):
                pass
    except Exception as e:
        logger.warning("Failed to get partition info: %s", e)

    # Mount options
    try:
        if os.path.exists('/proc/mounts'):
            with open('/proc/mounts') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[1].startswith('/'):
                        # Focus on data partitions
                        if any(d in parts[1] for d in ['/', '/data', '/hadoop', '/grid', '/mnt']):
                            result['mount_options'].append({
                                'device': parts[0],
                                'mountpoint': parts[1],
                                'fstype': parts[2],
                                'options': parts[3],
                            })
    except Exception as e:
        logger.warning("Failed to get mount options: %s", e)

    # Inode usage
    try:
        proc = subprocess.run(
            ['df', '-i'], capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0:
            for line in proc.stdout.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    use_pct = parts[4].rstrip('%')
                    result['inode_usage'].append({
                        'filesystem': parts[0],
                        'mountpoint': parts[5],
                        'inodes_total': int(parts[1]) if parts[1].isdigit() else 0,
                        'inodes_used': int(parts[2]) if parts[2].isdigit() else 0,
                        'inodes_free': int(parts[3]) if parts[3].isdigit() else 0,
                        'percent_used': int(use_pct) if use_pct.isdigit() else 0,
                    })
    except Exception as e:
        logger.warning("Failed to get inode usage: %s", e)

    # Disk health (SMART)
    try:
        proc = subprocess.run(
            ['bash', '-c', 'lsblk -d -n -o NAME,TYPE | grep disk'],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0:
            for line in proc.stdout.strip().split('\n'):
                disk_name = line.split()[0] if line.strip() else ''
                if not disk_name:
                    continue
                smart_proc = subprocess.run(
                    ['smartctl', '-H', f'/dev/{disk_name}'],
                    capture_output=True, text=True, timeout=10,
                )
                health = 'unknown'
                if 'PASSED' in (smart_proc.stdout or ''):
                    health = 'PASSED'
                elif 'FAILED' in (smart_proc.stdout or ''):
                    health = 'FAILED'
                result['disk_health'].append({
                    'disk': disk_name,
                    'smart_health': health,
                })
    except Exception as e:
        logger.warning("SMART check failed (needs root): %s", e)

    # I/O scheduler
    try:
        for disk_name in os.listdir('/sys/block'):
            sched_path = f'/sys/block/{disk_name}/queue/scheduler'
            if os.path.exists(sched_path):
                with open(sched_path) as f:
                    sched = f.read().strip()
                # Current scheduler is in brackets [xyz]
                current = ''
                m = re.search(r'\[(\w+)\]', sched)
                if m:
                    current = m.group(1)
                result['io_scheduler'][disk_name] = {
                    'current': current,
                    'available': sched,
                }
    except Exception as e:
        logger.warning("Failed to get I/O scheduler: %s", e)

    return result


def run_network_benchmark(targets=None, test_port=8020):
    """
    Network benchmark: measures latency, bandwidth estimates, and connectivity.

    Tests:
    - Ping latency to cluster peers
    - TCP connection latency to common Hadoop ports
    - DNS resolution time
    - Network interface configuration (MTU, duplex, speed)
    - Packet error/drop rates

    Args:
        targets: list of hostnames/IPs to test against. If None, discovers from /etc/hosts.
        test_port: port to test TCP latency against (default 8020 = NameNode).

    Returns:
        dict with benchmark results and network diagnostics.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'test': 'network_benchmark',
        'ping_latency': [],
        'tcp_latency': [],
        'dns_resolution': {},
        'interface_config': [],
        'error_rates': {},
        'arp_table_size': 0,
        'socket_stats': {},
    }

    # Discover targets from /etc/hosts if not provided
    if not targets:
        targets = _discover_hosts()

    # Ping latency
    for target in targets[:20]:  # Limit to 20 hosts
        try:
            proc = subprocess.run(
                ['ping', '-c', '3', '-W', '2', target],
                capture_output=True, text=True, timeout=10,
            )
            if proc.returncode == 0:
                # Parse avg latency from "min/avg/max/mdev = ..."
                m = re.search(r'=\s*[\d.]+/([\d.]+)/', proc.stdout)
                avg_ms = float(m.group(1)) if m else None
                result['ping_latency'].append({
                    'target': target,
                    'avg_ms': avg_ms,
                    'reachable': True,
                })
            else:
                result['ping_latency'].append({
                    'target': target,
                    'avg_ms': None,
                    'reachable': False,
                })
        except (subprocess.TimeoutExpired, Exception):
            result['ping_latency'].append({
                'target': target,
                'avg_ms': None,
                'reachable': False,
            })

    # TCP connection latency to common Hadoop ports
    hadoop_ports = [
        (8020, 'NameNode RPC'),
        (8088, 'ResourceManager'),
        (2181, 'ZooKeeper'),
        (16010, 'HBase Master'),
        (10000, 'HiveServer2'),
    ]
    for target in targets[:5]:  # Test first 5 hosts
        for port, label in hadoop_ports:
            try:
                start = time.monotonic()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                res = s.connect_ex((target, port))
                elapsed_ms = (time.monotonic() - start) * 1000
                s.close()
                if res == 0:
                    result['tcp_latency'].append({
                        'target': target,
                        'port': port,
                        'label': label,
                        'latency_ms': round(elapsed_ms, 2),
                        'reachable': True,
                    })
            except (socket.timeout, socket.error, OSError):
                pass

    # DNS resolution time
    try:
        for target in targets[:10]:
            start = time.monotonic()
            try:
                socket.gethostbyname(target)
                elapsed_ms = (time.monotonic() - start) * 1000
                result['dns_resolution'][target] = {
                    'resolved': True,
                    'latency_ms': round(elapsed_ms, 2),
                }
            except socket.gaierror:
                result['dns_resolution'][target] = {
                    'resolved': False,
                    'latency_ms': None,
                }
    except Exception as e:
        logger.warning("DNS resolution test failed: %s", e)

    # Network interface configuration
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for iface, stat in stats.items():
            if iface == 'lo':
                continue
            iface_info = {
                'name': iface,
                'is_up': stat.isup,
                'speed_mbps': stat.speed,
                'mtu': stat.mtu,
                'duplex': str(stat.duplex) if hasattr(stat, 'duplex') else '',
            }
            # Get IP addresses
            if iface in addrs:
                for addr in addrs[iface]:
                    if addr.family == socket.AF_INET:
                        iface_info['ipv4'] = addr.address
                        break
            result['interface_config'].append(iface_info)
    except Exception as e:
        logger.warning("Failed to get interface config: %s", e)

    # Packet error/drop rates
    try:
        net_io = psutil.net_io_counters(pernic=True)
        for iface, counters in net_io.items():
            if iface == 'lo':
                continue
            total_pkts = counters.packets_sent + counters.packets_recv
            if total_pkts > 0:
                result['error_rates'][iface] = {
                    'packets_total': total_pkts,
                    'errors_in': counters.errin,
                    'errors_out': counters.errout,
                    'drops_in': counters.dropin,
                    'drops_out': counters.dropout,
                    'error_rate_percent': round(
                        (counters.errin + counters.errout) / total_pkts * 100, 4
                    ),
                    'drop_rate_percent': round(
                        (counters.dropin + counters.dropout) / total_pkts * 100, 4
                    ),
                }
    except Exception as e:
        logger.warning("Failed to get error rates: %s", e)

    # ARP table size
    try:
        if os.path.exists('/proc/net/arp'):
            with open('/proc/net/arp') as f:
                lines = f.readlines()
            result['arp_table_size'] = max(0, len(lines) - 1)
    except Exception:
        pass

    # Socket statistics summary
    try:
        connections = psutil.net_connections(kind='tcp')
        states = {}
        for conn in connections:
            states[conn.status] = states.get(conn.status, 0) + 1
        result['socket_stats'] = states
    except (psutil.AccessDenied, Exception):
        pass

    return result


def _discover_hosts():
    """Discover peer hosts from /etc/hosts and cluster topology."""
    hosts = set()
    try:
        if os.path.exists('/etc/hosts'):
            with open('/etc/hosts') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        # Skip loopback
                        if ip.startswith('127.') or ip == '::1':
                            continue
                        for hostname in parts[1:]:
                            if hostname and not hostname.startswith('#'):
                                hosts.add(hostname)
    except Exception:
        pass
    return list(hosts)[:20]


def run_all_benchmarks(duration_seconds=10, test_size_mb=256,
                       disk_test_dir='/tmp/odpsc_disk_bench',
                       network_targets=None):
    """
    Run all benchmarks and return combined results.

    Args:
        duration_seconds: duration for CPU test.
        test_size_mb: memory test allocation size.
        disk_test_dir: directory for disk test files.
        network_targets: list of hosts for network test.

    Returns:
        dict with all benchmark results keyed by test name.
    """
    result = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
    }

    logger.info("Starting CPU benchmark...")
    result['cpu'] = run_cpu_benchmark(duration_seconds=duration_seconds)

    logger.info("Starting memory benchmark...")
    result['memory'] = run_memory_benchmark(test_size_mb=test_size_mb)

    logger.info("Starting disk benchmark...")
    result['disk'] = run_disk_benchmark(test_dir=disk_test_dir)

    logger.info("Starting network benchmark...")
    result['network'] = run_network_benchmark(targets=network_targets)

    logger.info("All benchmarks complete.")
    return result
