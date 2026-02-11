"""
ODPSC Agent - Runs on each cluster node to collect logs, metrics, configs and system info.
Sends collected data to the ODPSC Master for aggregation and analysis.
"""

import glob
import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timedelta

import psutil
import requests

LOG_DIR = '/var/log/odpsc'
PID_FILE = '/var/run/odpsc/agent.pid'
CONFIG_PATH = '/etc/odpsc/agent_config.json'
TEMP_DIR = '/tmp/odpsc'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'agent.log')) if os.path.isdir(LOG_DIR)
        else logging.StreamHandler(),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger('odpsc-agent')


DEFAULT_CONFIG = {
    'collection_enabled': True,
    'master_url': 'http://localhost:8085/api/v1/submit_data',
    'log_paths': ['/var/log/hadoop/*', '/var/log/hive/*', '/var/log/spark/*', '/var/log/yarn/*'],
    'config_paths': ['/etc/hadoop/conf/*'],
    'max_log_size_mb': 1,
    'log_retention_days': 7,
    'ambari_server_url': 'http://localhost:8080',
    'cluster_name': 'cluster',
}


def load_config(config_path=CONFIG_PATH):
    """Load agent configuration from JSON file, falling back to defaults."""
    config = DEFAULT_CONFIG.copy()
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
            config.update(user_config)
        except (json.JSONDecodeError, IOError) as e:
            logger.error("Failed to load config from %s: %s", config_path, e)
    else:
        logger.warning("Config file not found at %s, using defaults", config_path)
    return config


def collect_logs(log_path_patterns, max_size_mb=1, retention_days=7):
    """
    Collect log files matching the given glob patterns.
    Only includes content from the last `retention_days` days,
    truncated to `max_size_mb` per file.

    Returns:
        dict mapping file paths to their (truncated) content.
    """
    logs = {}
    max_bytes = max_size_mb * 1024 * 1024
    cutoff_time = time.time() - (retention_days * 86400)

    for pattern in log_path_patterns:
        for filepath in glob.glob(pattern):
            if not os.path.isfile(filepath):
                continue
            try:
                # Skip files not modified within retention period
                if os.path.getmtime(filepath) < cutoff_time:
                    continue
                with open(filepath, 'r', errors='replace') as f:
                    # Read last max_bytes of the file
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    start = max(0, size - max_bytes)
                    f.seek(start)
                    content = f.read()
                logs[filepath] = content
                logger.info("Collected log: %s (%d bytes)", filepath, len(content))
            except (IOError, OSError) as e:
                logger.error("Failed to read log %s: %s", filepath, e)

    return logs


def collect_metrics(ambari_server_url=None, cluster_name=None):
    """
    Collect system metrics using psutil and optionally from Ambari Metrics API.

    Returns:
        dict with system and (optionally) Ambari metrics.
    """
    metrics = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'hostname': socket.getfqdn(),
        'system': {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'cpu_count': psutil.cpu_count(),
            'memory': dict(psutil.virtual_memory()._asdict()),
            'swap': dict(psutil.swap_memory()._asdict()),
            'disk_usage': {},
            'disk_io': None,
            'net_io': None,
            'load_avg': list(os.getloadavg()) if hasattr(os, 'getloadavg') else None,
        },
    }

    # Disk usage for all mounted partitions
    try:
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                metrics['system']['disk_usage'][part.mountpoint] = dict(usage._asdict())
            except (PermissionError, OSError):
                pass
    except Exception as e:
        logger.error("Failed to collect disk partitions: %s", e)

    # Disk I/O counters
    try:
        disk_io = psutil.disk_io_counters()
        if disk_io:
            metrics['system']['disk_io'] = dict(disk_io._asdict())
    except Exception as e:
        logger.error("Failed to collect disk I/O: %s", e)

    # Network I/O counters
    try:
        net_io = psutil.net_io_counters()
        if net_io:
            metrics['system']['net_io'] = dict(net_io._asdict())
    except Exception as e:
        logger.error("Failed to collect network I/O: %s", e)

    # Ambari Metrics (if configured)
    if ambari_server_url and cluster_name:
        try:
            url = (
                f"{ambari_server_url}/api/v1/clusters/{cluster_name}"
                f"/hosts/{socket.getfqdn()}/host_components"
            )
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                metrics['ambari'] = resp.json()
            else:
                logger.warning(
                    "Ambari metrics request returned %d", resp.status_code
                )
        except requests.RequestException as e:
            logger.warning("Failed to fetch Ambari metrics: %s", e)

    return metrics


def collect_configs(config_path_patterns):
    """
    Collect configuration files matching the given glob patterns.
    Masks sensitive values (passwords, secrets, tokens).

    Returns:
        dict mapping file paths to their (sanitized) content.
    """
    configs = {}
    sensitive_patterns = [
        'password', 'secret', 'token', 'key', 'credential',
    ]

    for pattern in config_path_patterns:
        for filepath in glob.glob(pattern):
            if not os.path.isfile(filepath):
                continue
            try:
                with open(filepath, 'r', errors='replace') as f:
                    content = f.read()

                # Mask sensitive values in XML properties
                for sensitive in sensitive_patterns:
                    # XML: <value>...</value> after a <name> containing sensitive word
                    import re
                    content = re.sub(
                        rf'(<name>[^<]*{sensitive}[^<]*</name>\s*<value>)[^<]*(</value>)',
                        r'\1****MASKED****\2',
                        content,
                        flags=re.IGNORECASE,
                    )
                    # JSON-like: "key": "value"
                    content = re.sub(
                        rf'("{sensitive}[^"]*"\s*:\s*")[^"]*(")',
                        r'\1****MASKED****\2',
                        content,
                        flags=re.IGNORECASE,
                    )

                configs[filepath] = content
                logger.info("Collected config: %s", filepath)
            except (IOError, OSError) as e:
                logger.error("Failed to read config %s: %s", filepath, e)

    return configs


def collect_system_info():
    """
    Collect basic system information.

    Returns:
        dict with hostname, OS, Java version, etc.
    """
    info = {
        'hostname': socket.getfqdn(),
        'ip_address': _get_ip_address(),
        'os': {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
        },
        'python_version': platform.python_version(),
        'java_version': _get_java_version(),
        'uptime_seconds': time.time() - psutil.boot_time(),
        'timestamp': datetime.now(tz=None).isoformat(),
    }
    return info


def _get_ip_address():
    """Get the primary IP address of the host."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def _get_java_version():
    """Get the installed Java version."""
    try:
        result = subprocess.run(
            ['java', '-version'],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stderr or result.stdout
        return output.strip().split('\n')[0] if output else 'unknown'
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 'not installed'


def create_bundle(data, temp_dir=TEMP_DIR):
    """
    Create a ZIP bundle from collected data.

    Args:
        data: dict with keys 'logs', 'metrics', 'configs', 'system_info'.
        temp_dir: directory for temporary files.

    Returns:
        Path to the created ZIP file.
    """
    os.makedirs(temp_dir, exist_ok=True)
    hostname = socket.getfqdn()
    timestamp = datetime.now(tz=None).strftime('%Y%m%d_%H%M%S')
    zip_filename = f'odpsc_agent_{hostname}_{timestamp}.zip'
    zip_path = os.path.join(temp_dir, zip_filename)

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Add logs
        for filepath, content in data.get('logs', {}).items():
            arcname = f'logs/{os.path.basename(filepath)}'
            zf.writestr(arcname, content)

        # Add metrics
        zf.writestr('metrics.json', json.dumps(data.get('metrics', {}), indent=2))

        # Add configs
        for filepath, content in data.get('configs', {}).items():
            arcname = f'configs/{os.path.basename(filepath)}'
            zf.writestr(arcname, content)

        # Add system info
        zf.writestr('system_info.json', json.dumps(data.get('system_info', {}), indent=2))

    logger.info("Created bundle: %s", zip_path)
    return zip_path


def send_to_master(zip_path, master_url):
    """
    Send the agent bundle ZIP to the ODPSC Master.

    Args:
        zip_path: path to the ZIP file.
        master_url: URL of the master's submit_data endpoint.

    Returns:
        True if successful, False otherwise.
    """
    try:
        with open(zip_path, 'rb') as f:
            resp = requests.post(
                master_url,
                files={'bundle': (os.path.basename(zip_path), f, 'application/zip')},
                timeout=120,
            )
        if resp.status_code == 200:
            logger.info("Successfully sent bundle to master")
            return True
        else:
            logger.error(
                "Master returned status %d: %s", resp.status_code, resp.text
            )
            return False
    except requests.RequestException as e:
        logger.error("Failed to send bundle to master: %s", e)
        return False


def cleanup(temp_dir=TEMP_DIR):
    """Remove temporary files."""
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)
        logger.info("Cleaned up temp directory: %s", temp_dir)


def run_collection(config):
    """
    Execute a full collection cycle: collect data, bundle, send to master, cleanup.

    Args:
        config: agent configuration dict.

    Returns:
        True if successful, False otherwise.
    """
    if not config.get('collection_enabled', True):
        logger.info("Collection is disabled, skipping")
        return False

    logger.info("Starting collection cycle")
    try:
        data = {
            'logs': collect_logs(
                config.get('log_paths', []),
                max_size_mb=config.get('max_log_size_mb', 1),
                retention_days=config.get('log_retention_days', 7),
            ),
            'metrics': collect_metrics(
                ambari_server_url=config.get('ambari_server_url'),
                cluster_name=config.get('cluster_name'),
            ),
            'configs': collect_configs(config.get('config_paths', [])),
            'system_info': collect_system_info(),
        }

        zip_path = create_bundle(data)
        success = send_to_master(zip_path, config['master_url'])
        cleanup()
        return success

    except Exception as e:
        logger.exception("Collection cycle failed: %s", e)
        cleanup()
        return False


def write_pid():
    """Write the current PID to the PID file."""
    os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))


def remove_pid():
    """Remove the PID file."""
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)


def is_running():
    """Check if the agent is already running."""
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            return psutil.pid_exists(pid)
        except (ValueError, IOError):
            return False
    return False


def main():
    """Main entry point for the ODPSC Agent."""
    if is_running():
        logger.error("Agent is already running")
        sys.exit(1)

    write_pid()
    try:
        config = load_config()
        success = run_collection(config)
        sys.exit(0 if success else 1)
    finally:
        remove_pid()


if __name__ == '__main__':
    main()
