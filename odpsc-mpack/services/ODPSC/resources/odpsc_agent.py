"""
ODPSC Agent v2 - Runs on each cluster node to collect logs, metrics, configs and system info.
Stages bundles locally and uploads to the ODPSC Master with API key auth and retry logic.
"""

import argparse
import glob
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timedelta

import psutil
import requests

LOG_DIR = '/var/log/odpsc'
CONFIG_PATH = '/etc/odpsc/agent_config.json'

AGENT_BASE_DIR = '/var/lib/odpsc/agent'
OUTBOX_DIR = os.path.join(AGENT_BASE_DIR, 'outbox')
SENT_DIR = os.path.join(AGENT_BASE_DIR, 'sent')
FAILED_DIR = os.path.join(AGENT_BASE_DIR, 'failed')
RETRY_STATE_FILE = os.path.join(AGENT_BASE_DIR, 'retry_state.json')

SENT_CLEANUP_DAYS = 7
MAX_RETRY_ATTEMPTS = 10
RETRY_BASE_DELAY = 30
RETRY_MAX_DELAY = 300

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
    'master_url': 'http://localhost:8085',
    'api_key': '',
    'bundle_level': 'L1',
    'log_paths': ['/var/log/hadoop/*', '/var/log/hive/*', '/var/log/spark/*', '/var/log/yarn/*'],
    'config_paths': ['/etc/hadoop/conf/*'],
    'max_log_size_mb': 1,
    'log_retention_days': 7,
    'ambari_server_url': 'http://localhost:8080',
    'cluster_name': 'cluster',
}

# Sensitive data patterns for masking
SENSITIVE_PATTERNS = [
    'password', 'secret', 'token', 'key', 'credential',
]

# Hadoop-specific sensitive patterns
HADOOP_SENSITIVE_PATTERNS = [
    # JDBC passwords
    (re.compile(
        r'(jdbc:[^\s]*[?&;]password=)[^\s&;]*',
        re.IGNORECASE,
    ), r'\1****MASKED****'),
    # AWS/S3 keys
    (re.compile(
        r'((?:fs\.s3a?\.|aws\.)\S*(?:access|secret)[.\w]*\s*[=:]\s*)[^\s<"]+',
        re.IGNORECASE,
    ), r'\1****MASKED****'),
    # Azure storage keys
    (re.compile(
        r'((?:fs\.azure\.|dfs\.adls\.)\S*(?:key|secret|token)[.\w]*\s*[=:]\s*)[^\s<"]+',
        re.IGNORECASE,
    ), r'\1****MASKED****'),
    # Kerberos keytab paths (mark but don't mask path itself - mask surrounding secrets)
    (re.compile(
        r'(keytab\s*[=:]\s*)[^\s<"]+',
        re.IGNORECASE,
    ), r'\1****MASKED****'),
    # LDAP bind passwords
    (re.compile(
        r'((?:bind|ldap)[._]?password\s*[=:]\s*)[^\s<"]+',
        re.IGNORECASE,
    ), r'\1****MASKED****'),
    # SSL keystore/truststore passwords
    (re.compile(
        r'((?:keystore|truststore)[._]?password\s*[=:]\s*)[^\s<"]+',
        re.IGNORECASE,
    ), r'\1****MASKED****'),
]


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


def ensure_dirs():
    """Ensure all staging directories exist."""
    for d in (OUTBOX_DIR, SENT_DIR, FAILED_DIR):
        os.makedirs(d, exist_ok=True)


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
                if os.path.getmtime(filepath) < cutoff_time:
                    continue
                with open(filepath, 'r', errors='replace') as f:
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

    try:
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                metrics['system']['disk_usage'][part.mountpoint] = dict(usage._asdict())
            except (PermissionError, OSError):
                pass
    except Exception as e:
        logger.error("Failed to collect disk partitions: %s", e)

    try:
        disk_io = psutil.disk_io_counters()
        if disk_io:
            metrics['system']['disk_io'] = dict(disk_io._asdict())
    except Exception as e:
        logger.error("Failed to collect disk I/O: %s", e)

    try:
        net_io = psutil.net_io_counters()
        if net_io:
            metrics['system']['net_io'] = dict(net_io._asdict())
    except Exception as e:
        logger.error("Failed to collect network I/O: %s", e)

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
    Masks sensitive values (passwords, secrets, tokens) including Hadoop-specific patterns.

    Returns:
        dict mapping file paths to their (sanitized) content.
    """
    configs = {}

    for pattern in config_path_patterns:
        for filepath in glob.glob(pattern):
            if not os.path.isfile(filepath):
                continue
            try:
                with open(filepath, 'r', errors='replace') as f:
                    content = f.read()

                content = mask_sensitive_data(content)
                configs[filepath] = content
                logger.info("Collected config: %s", filepath)
            except (IOError, OSError) as e:
                logger.error("Failed to read config %s: %s", filepath, e)

    return configs


def mask_sensitive_data(content):
    """Mask sensitive values in configuration content."""
    # XML property masking: <name>...password...</name><value>secret</value>
    for sensitive in SENSITIVE_PATTERNS:
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

    # Hadoop-specific patterns
    for pattern, replacement in HADOOP_SENSITIVE_PATTERNS:
        content = pattern.sub(replacement, content)

    return content


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


def create_bundle(data, bundle_id, level, dest_dir):
    """
    Create a ZIP bundle with manifest from collected data.

    Args:
        data: dict with keys 'logs', 'metrics', 'configs', 'system_info'.
        bundle_id: UUID string for the bundle.
        level: bundle level (L1, L2, L3).
        dest_dir: directory to write the bundle to.

    Returns:
        Path to the created ZIP file.
    """
    os.makedirs(dest_dir, exist_ok=True)
    hostname = socket.getfqdn()
    timestamp = datetime.now(tz=None).strftime('%Y%m%d_%H%M%S')
    zip_filename = f'odpsc_agent_{hostname}_{timestamp}_{bundle_id[:8]}.zip'
    zip_path = os.path.join(dest_dir, zip_filename)

    manifest = {
        'bundle_id': bundle_id,
        'hostname': hostname,
        'ip_address': _get_ip_address(),
        'level': level,
        'timestamp': datetime.now(tz=None).isoformat(),
        'odpsc_version': '2.0',
        'contents': [],
    }

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Always include configs and system_info (L1+)
        for filepath, content in data.get('configs', {}).items():
            arcname = f'configs/{os.path.basename(filepath)}'
            zf.writestr(arcname, content)
            manifest['contents'].append(arcname)

        zf.writestr('system_info.json', json.dumps(data.get('system_info', {}), indent=2))
        manifest['contents'].append('system_info.json')

        # L2+: include metrics
        if level in ('L2', 'L3'):
            zf.writestr('metrics.json', json.dumps(data.get('metrics', {}), indent=2))
            manifest['contents'].append('metrics.json')

        # L3: include logs
        if level == 'L3':
            for filepath, content in data.get('logs', {}).items():
                arcname = f'logs/{os.path.basename(filepath)}'
                zf.writestr(arcname, content)
                manifest['contents'].append(arcname)

        zf.writestr('manifest.json', json.dumps(manifest, indent=2))

    logger.info("Created bundle: %s (level=%s, id=%s)", zip_path, level, bundle_id)
    return zip_path


def upload_bundle(zip_path, master_url, api_key, bundle_id):
    """
    Upload a bundle to the ODPSC Master with API key auth.

    Args:
        zip_path: path to the ZIP file.
        master_url: base URL of the master (e.g. http://master:8085).
        api_key: API key for authentication.
        bundle_id: UUID of the bundle.

    Returns:
        tuple (success: bool, status: str)
    """
    upload_url = f"{master_url.rstrip('/')}/api/v2/bundles/upload"
    headers = {
        'Authorization': f'Bearer {api_key}',
        'X-ODPSC-Bundle-ID': bundle_id,
    }

    try:
        with open(zip_path, 'rb') as f:
            resp = requests.post(
                upload_url,
                files={'bundle': (os.path.basename(zip_path), f, 'application/zip')},
                headers=headers,
                timeout=120,
            )
        if resp.status_code == 200:
            data = resp.json()
            status = data.get('status', 'received')
            logger.info("Bundle uploaded successfully (status=%s)", status)
            return True, status
        elif resp.status_code == 401:
            logger.error("Authentication failed - check API key")
            return False, 'auth_failed'
        elif resp.status_code == 429:
            logger.warning("Rate limited by master")
            return False, 'rate_limited'
        else:
            logger.error(
                "Master returned status %d: %s", resp.status_code, resp.text
            )
            return False, f'http_{resp.status_code}'
    except requests.RequestException as e:
        logger.error("Failed to upload bundle to master: %s", e)
        return False, 'connection_error'


def run_collection(config, level=None):
    """
    Execute a full collection cycle: collect data, bundle, stage to outbox.

    Args:
        config: agent configuration dict.
        level: override bundle level (L1, L2, L3). If None, uses config.

    Returns:
        Path to the staged bundle, or None on failure.
    """
    if not config.get('collection_enabled', True):
        logger.info("Collection is disabled, skipping")
        return None

    if level is None:
        level = config.get('bundle_level', 'L1')

    level = level.upper()
    if level not in ('L1', 'L2', 'L3'):
        logger.error("Invalid bundle level: %s", level)
        return None

    logger.info("Starting collection cycle (level=%s)", level)
    bundle_id = str(uuid.uuid4())

    try:
        data = {}

        # L1: configs + system_info (always collected)
        data['configs'] = collect_configs(config.get('config_paths', []))
        data['system_info'] = collect_system_info()

        # L2+: metrics
        if level in ('L2', 'L3'):
            data['metrics'] = collect_metrics(
                ambari_server_url=config.get('ambari_server_url'),
                cluster_name=config.get('cluster_name'),
            )

        # L3: logs
        if level == 'L3':
            data['logs'] = collect_logs(
                config.get('log_paths', []),
                max_size_mb=config.get('max_log_size_mb', 1),
                retention_days=config.get('log_retention_days', 7),
            )

        ensure_dirs()
        zip_path = create_bundle(data, bundle_id, level, OUTBOX_DIR)

        # Try immediate upload
        master_url = config.get('master_url', 'http://localhost:8085')
        api_key = config.get('api_key', '')
        success, status = upload_bundle(zip_path, master_url, api_key, bundle_id)

        if success:
            _move_to_sent(zip_path)
        else:
            logger.info("Bundle staged in outbox for retry: %s", zip_path)
            _update_retry_state(zip_path, bundle_id)

        return zip_path

    except Exception as e:
        logger.exception("Collection cycle failed: %s", e)
        return None


def _move_to_sent(zip_path):
    """Move a successfully uploaded bundle to the sent directory."""
    ensure_dirs()
    dest = os.path.join(SENT_DIR, os.path.basename(zip_path))
    try:
        shutil.move(zip_path, dest)
        logger.info("Bundle moved to sent: %s", dest)
    except (IOError, OSError) as e:
        logger.error("Failed to move bundle to sent: %s", e)


def _move_to_failed(zip_path):
    """Move a permanently failed bundle to the failed directory."""
    ensure_dirs()
    dest = os.path.join(FAILED_DIR, os.path.basename(zip_path))
    try:
        shutil.move(zip_path, dest)
        logger.info("Bundle moved to failed: %s", dest)
    except (IOError, OSError) as e:
        logger.error("Failed to move bundle to failed: %s", e)


def _load_retry_state():
    """Load retry state from disk."""
    if os.path.exists(RETRY_STATE_FILE):
        try:
            with open(RETRY_STATE_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def _save_retry_state(state):
    """Save retry state to disk."""
    ensure_dirs()
    try:
        with open(RETRY_STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2)
    except IOError as e:
        logger.error("Failed to save retry state: %s", e)


def _update_retry_state(zip_path, bundle_id):
    """Add or update retry state for a bundle."""
    state = _load_retry_state()
    filename = os.path.basename(zip_path)
    if filename not in state:
        state[filename] = {
            'bundle_id': bundle_id,
            'attempts': 0,
            'last_attempt': None,
        }
    _save_retry_state(state)


def retry_pending(config):
    """
    Scan outbox for pending bundles and retry uploads with exponential backoff.

    Args:
        config: agent configuration dict.
    """
    ensure_dirs()
    master_url = config.get('master_url', 'http://localhost:8085')
    api_key = config.get('api_key', '')
    state = _load_retry_state()

    outbox_files = [
        f for f in os.listdir(OUTBOX_DIR)
        if f.endswith('.zip')
    ]

    if not outbox_files:
        logger.info("No pending bundles in outbox")
        return

    logger.info("Found %d pending bundle(s) in outbox", len(outbox_files))

    for filename in sorted(outbox_files):
        zip_path = os.path.join(OUTBOX_DIR, filename)

        entry = state.get(filename, {
            'bundle_id': str(uuid.uuid4()),
            'attempts': 0,
            'last_attempt': None,
        })

        attempts = entry.get('attempts', 0)

        if attempts >= MAX_RETRY_ATTEMPTS:
            logger.warning("Bundle exceeded max retries (%d), moving to failed: %s",
                           MAX_RETRY_ATTEMPTS, filename)
            _move_to_failed(zip_path)
            state.pop(filename, None)
            continue

        # Check backoff delay
        last_attempt = entry.get('last_attempt')
        if last_attempt:
            delay = min(RETRY_MAX_DELAY, RETRY_BASE_DELAY * (2 ** attempts))
            elapsed = time.time() - last_attempt
            if elapsed < delay:
                logger.debug("Skipping %s: backoff %ds, elapsed %ds",
                             filename, delay, elapsed)
                continue

        bundle_id = entry.get('bundle_id', str(uuid.uuid4()))
        logger.info("Retrying upload for %s (attempt %d/%d)",
                     filename, attempts + 1, MAX_RETRY_ATTEMPTS)

        success, status = upload_bundle(zip_path, master_url, api_key, bundle_id)

        if success:
            _move_to_sent(zip_path)
            state.pop(filename, None)
        else:
            entry['attempts'] = attempts + 1
            entry['last_attempt'] = time.time()
            state[filename] = entry

    _save_retry_state(state)


def cleanup_sent(max_age_days=SENT_CLEANUP_DAYS):
    """Remove sent bundles older than max_age_days."""
    ensure_dirs()
    cutoff = time.time() - (max_age_days * 86400)
    removed = 0

    for filename in os.listdir(SENT_DIR):
        filepath = os.path.join(SENT_DIR, filename)
        try:
            if os.path.getmtime(filepath) < cutoff:
                os.remove(filepath)
                removed += 1
        except OSError:
            pass

    if removed:
        logger.info("Cleaned up %d sent bundle(s) older than %d days", removed, max_age_days)


def main():
    """Main entry point for the ODPSC Agent v2."""
    parser = argparse.ArgumentParser(description='ODPSC Agent v2 - Diagnostic collection agent')
    parser.add_argument(
        '--collect', action='store_true',
        help='Run a collection cycle',
    )
    parser.add_argument(
        '--level', choices=['L1', 'L2', 'L3'], default=None,
        help='Bundle level: L1 (configs+sysinfo), L2 (+metrics), L3 (+logs)',
    )
    parser.add_argument(
        '--retry', action='store_true',
        help='Retry pending uploads from outbox',
    )
    parser.add_argument(
        '--cleanup', action='store_true',
        help='Clean up old sent bundles',
    )
    parser.add_argument(
        '--config', default=CONFIG_PATH,
        help='Path to agent configuration file',
    )

    args = parser.parse_args()
    config = load_config(args.config)

    if not any([args.collect, args.retry, args.cleanup]):
        # Default: collect and retry
        args.collect = True
        args.retry = True
        args.cleanup = True

    if args.collect:
        run_collection(config, level=args.level)

    if args.retry:
        retry_pending(config)

    if args.cleanup:
        cleanup_sent()


if __name__ == '__main__':
    main()
