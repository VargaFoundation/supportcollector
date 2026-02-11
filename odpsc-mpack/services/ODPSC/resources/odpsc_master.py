"""
ODPSC Master - Flask server that receives agent data, aggregates, analyzes,
and either sends bundles to support or stores them in HDFS.
"""

import base64
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from datetime import datetime
from functools import wraps
from io import BytesIO

import requests
import schedule
from cryptography.fernet import Fernet
from flask import Flask, Response, jsonify, request

from analyzer import analyze_logs, generate_text_report

LOG_DIR = '/var/log/odpsc'
PID_FILE = '/var/run/odpsc/master.pid'
CONFIG_PATH = '/etc/odpsc/master_config.json'
DATA_DIR = '/tmp/odpsc/master_data'
BUNDLE_DIR = '/tmp/odpsc/bundles'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'master.log')) if os.path.isdir(LOG_DIR)
        else logging.StreamHandler(),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger('odpsc-master')


DEFAULT_CONFIG = {
    'collection_enabled': True,
    'auto_send_enabled': True,
    'send_frequency': 'weekly',
    'support_endpoint': 'https://support.odp.com/upload',
    'support_token': '',
    'hdfs_path': '/odpsc/diagnostics',
    'master_port': 8085,
    'admin_username': 'admin',
    'admin_password': 'admin',
    'encryption_key': '',
    'log_paths': ['/var/log/hadoop/*', '/var/log/hive/*', '/var/log/spark/*', '/var/log/yarn/*'],
    'ambari_server_url': 'http://localhost:8080',
    'cluster_name': 'cluster',
}


def load_config(config_path=CONFIG_PATH):
    """Load master configuration from JSON file, falling back to defaults."""
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


def save_config(config, config_path=None):
    """Persist configuration to disk."""
    if config_path is None:
        config_path = CONFIG_PATH
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    logger.info("Configuration saved to %s", config_path)


def create_app(config=None):
    """Create and configure the Flask application."""
    app = Flask(__name__)

    if config is None:
        config = load_config()
    app.config['ODPSC'] = config

    # Ensure working directories exist
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(BUNDLE_DIR, exist_ok=True)

    def get_config():
        return app.config['ODPSC']

    def require_auth(f):
        """Decorator for Basic Auth on protected endpoints."""
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.authorization
            cfg = get_config()
            if (not auth
                    or auth.username != cfg.get('admin_username', 'admin')
                    or auth.password != cfg.get('admin_password', 'admin')):
                return Response(
                    json.dumps({'error': 'Unauthorized'}),
                    status=401,
                    mimetype='application/json',
                    headers={'WWW-Authenticate': 'Basic realm="ODPSC"'},
                )
            return f(*args, **kwargs)
        return decorated

    @app.route('/api/v1/submit_data', methods=['POST'])
    def receive_data():
        """Receive a diagnostic bundle from an agent."""
        if 'bundle' not in request.files:
            return jsonify({'error': 'No bundle file provided'}), 400

        bundle_file = request.files['bundle']
        if not bundle_file.filename:
            return jsonify({'error': 'Empty filename'}), 400

        # Save the bundle to the data directory
        timestamp = datetime.now(tz=None).strftime('%Y%m%d_%H%M%S')
        safe_name = f"agent_{timestamp}_{bundle_file.filename}"
        save_path = os.path.join(DATA_DIR, safe_name)

        bundle_file.save(save_path)
        logger.info("Received agent bundle: %s", save_path)

        return jsonify({'status': 'received', 'filename': safe_name})

    @app.route('/api/v1/collect', methods=['POST'])
    @require_auth
    def manual_collect():
        """Trigger a manual collection cycle."""
        cfg = get_config()

        if not cfg.get('collection_enabled', True):
            return jsonify({'error': 'Collection is disabled'}), 403

        send = False
        if request.is_json and request.json:
            send = request.json.get('send', False)

        try:
            # Trigger collection on agents via Ambari API
            _trigger_agent_collection(cfg)

            # Wait a bit for agents to submit data
            time.sleep(5)

            # Aggregate all received data
            aggregated = _aggregate_data()

            # Analyze logs
            analysis = analyze_logs(aggregated.get('logs', {}))
            aggregated['analysis'] = analysis
            aggregated['analysis_report'] = generate_text_report(analysis)

            # Create the final bundle
            zip_path = _create_master_bundle(aggregated, cfg)

            if send and cfg.get('auto_send_enabled', True):
                success = _send_to_support(zip_path, cfg)
                if not success:
                    return jsonify({
                        'status': 'error',
                        'message': 'Failed to send bundle to support',
                        'zip': zip_path,
                    }), 500
                return jsonify({'status': 'sent', 'zip': zip_path})
            else:
                hdfs_path = _put_to_hdfs(zip_path, cfg)
                return jsonify({'status': 'done', 'zip': zip_path, 'hdfs_path': hdfs_path})

        except Exception as e:
            logger.exception("Manual collection failed: %s", e)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v1/config', methods=['GET'])
    @require_auth
    def get_configuration():
        """Return the current configuration (sensitive fields masked)."""
        cfg = get_config().copy()
        # Mask sensitive values
        for key in ('support_token', 'admin_password', 'encryption_key'):
            if cfg.get(key):
                cfg[key] = '****MASKED****'
        return jsonify(cfg)

    @app.route('/api/v1/config', methods=['POST'])
    @require_auth
    def update_configuration():
        """Update configuration properties."""
        if not request.is_json:
            return jsonify({'error': 'JSON body required'}), 400

        updates = request.json
        cfg = get_config()

        # Whitelist of updatable properties
        updatable = {
            'collection_enabled', 'auto_send_enabled', 'send_frequency',
            'support_endpoint', 'support_token', 'hdfs_path', 'log_paths',
            'admin_username', 'admin_password', 'encryption_key',
            'log_retention_days', 'max_log_size_mb',
        }

        applied = {}
        for key, value in updates.items():
            if key in updatable:
                cfg[key] = value
                applied[key] = value

        if applied:
            app.config['ODPSC'] = cfg
            save_config(cfg)
            # Reschedule if frequency changed
            if 'send_frequency' in applied:
                _setup_scheduler(cfg)

        return jsonify({'status': 'updated', 'applied': list(applied.keys())})

    @app.route('/api/v1/status', methods=['GET'])
    @require_auth
    def get_status():
        """Return the current status of the ODPSC Master."""
        cfg = get_config()
        agent_bundles = []
        if os.path.isdir(DATA_DIR):
            agent_bundles = os.listdir(DATA_DIR)

        return jsonify({
            'status': 'running',
            'collection_enabled': cfg.get('collection_enabled', True),
            'auto_send_enabled': cfg.get('auto_send_enabled', True),
            'send_frequency': cfg.get('send_frequency', 'weekly'),
            'agent_bundles_received': len(agent_bundles),
            'timestamp': datetime.now(tz=None).isoformat(),
        })

    return app


def _trigger_agent_collection(config):
    """
    Trigger agent collection by requesting Ambari to execute
    a custom action on all ODPSC_AGENT components.
    """
    ambari_url = config.get('ambari_server_url', 'http://localhost:8080')
    cluster_name = config.get('cluster_name', 'cluster')

    try:
        url = f"{ambari_url}/api/v1/clusters/{cluster_name}/requests"
        payload = {
            "RequestInfo": {
                "context": "ODPSC Agent Collection",
                "command": "COLLECT",
            },
            "Requests/resource_filters": [{
                "service_name": "ODPSC",
                "component_name": "ODPSC_AGENT",
            }],
        }
        resp = requests.post(url, json=payload, timeout=30)
        logger.info(
            "Triggered agent collection via Ambari (status %d)", resp.status_code
        )
    except requests.RequestException as e:
        logger.warning(
            "Failed to trigger agents via Ambari, agents may need manual trigger: %s", e
        )


def _aggregate_data():
    """
    Aggregate all data received from agents.
    Extracts and merges the contents of all agent bundle ZIPs.
    """
    aggregated = {
        'logs': {},
        'metrics': [],
        'configs': {},
        'system_info': [],
        'agent_count': 0,
    }

    if not os.path.isdir(DATA_DIR):
        return aggregated

    for filename in os.listdir(DATA_DIR):
        filepath = os.path.join(DATA_DIR, filename)
        if not filename.endswith('.zip'):
            continue

        try:
            with zipfile.ZipFile(filepath, 'r') as zf:
                for name in zf.namelist():
                    content = zf.read(name).decode('utf-8', errors='replace')

                    if name.startswith('logs/'):
                        log_key = f"{filename}:{name}"
                        aggregated['logs'][log_key] = content
                    elif name == 'metrics.json':
                        try:
                            aggregated['metrics'].append(json.loads(content))
                        except json.JSONDecodeError:
                            pass
                    elif name.startswith('configs/'):
                        config_key = f"{filename}:{name}"
                        aggregated['configs'][config_key] = content
                    elif name == 'system_info.json':
                        try:
                            aggregated['system_info'].append(json.loads(content))
                        except json.JSONDecodeError:
                            pass

            aggregated['agent_count'] += 1
        except zipfile.BadZipFile:
            logger.error("Bad zip file: %s", filepath)

    logger.info(
        "Aggregated data from %d agent(s): %d log files, %d metrics entries",
        aggregated['agent_count'],
        len(aggregated['logs']),
        len(aggregated['metrics']),
    )
    return aggregated


def _create_master_bundle(aggregated, config):
    """
    Create the final master bundle ZIP file, optionally encrypted.

    Returns:
        Path to the created ZIP file.
    """
    os.makedirs(BUNDLE_DIR, exist_ok=True)
    timestamp = datetime.now(tz=None).strftime('%Y%m%d_%H%M%S')
    zip_filename = f'odpsc_bundle_{timestamp}.zip'
    zip_path = os.path.join(BUNDLE_DIR, zip_filename)

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Aggregated logs
        for key, content in aggregated.get('logs', {}).items():
            safe_key = key.replace(':', '_').replace('/', '_')
            zf.writestr(f'logs/{safe_key}', content)

        # Metrics
        zf.writestr('metrics.json', json.dumps(aggregated.get('metrics', []), indent=2))

        # Configs
        for key, content in aggregated.get('configs', {}).items():
            safe_key = key.replace(':', '_').replace('/', '_')
            zf.writestr(f'configs/{safe_key}', content)

        # System info
        zf.writestr('system_info.json', json.dumps(aggregated.get('system_info', []), indent=2))

        # Analysis report
        if 'analysis' in aggregated:
            zf.writestr('analysis.json', json.dumps(aggregated['analysis'], indent=2))
        if 'analysis_report' in aggregated:
            zf.writestr('analysis_report.txt', aggregated['analysis_report'])

        # Metadata
        metadata = {
            'created': timestamp,
            'agent_count': aggregated.get('agent_count', 0),
            'odpsc_version': '1.0',
        }
        zf.writestr('metadata.json', json.dumps(metadata, indent=2))

    # Encrypt if key is configured
    encryption_key = config.get('encryption_key')
    if encryption_key:
        zip_path = _encrypt_bundle(zip_path, encryption_key)

    logger.info("Created master bundle: %s", zip_path)
    return zip_path


def _encrypt_bundle(zip_path, encryption_key):
    """
    Encrypt a bundle file using Fernet (AES-128-CBC via cryptography lib).
    For AES-256 we derive a key via SHA-256 if the provided key is not valid Fernet.
    """
    try:
        # Try using the key directly as Fernet key
        key = encryption_key.encode() if isinstance(encryption_key, str) else encryption_key
        # Derive a proper Fernet key from arbitrary input
        derived = base64.urlsafe_b64encode(hashlib.sha256(key).digest())
        fernet = Fernet(derived)

        with open(zip_path, 'rb') as f:
            data = f.read()

        encrypted = fernet.encrypt(data)
        encrypted_path = zip_path + '.enc'

        with open(encrypted_path, 'wb') as f:
            f.write(encrypted)

        os.remove(zip_path)
        logger.info("Encrypted bundle: %s", encrypted_path)
        return encrypted_path

    except Exception as e:
        logger.error("Encryption failed, keeping unencrypted bundle: %s", e)
        return zip_path


def _send_to_support(zip_path, config):
    """Send the bundle to the support endpoint via HTTPS."""
    endpoint = config.get('support_endpoint')
    token = config.get('support_token')

    if not endpoint:
        logger.error("No support endpoint configured")
        return False

    headers = {}
    if token:
        headers['Authorization'] = f'Bearer {token}'

    try:
        with open(zip_path, 'rb') as f:
            resp = requests.post(
                endpoint,
                files={'bundle': (os.path.basename(zip_path), f, 'application/zip')},
                headers=headers,
                timeout=300,
            )
        if resp.status_code in (200, 201):
            logger.info("Bundle sent to support successfully")
            return True
        else:
            logger.error(
                "Support endpoint returned %d: %s", resp.status_code, resp.text
            )
            return False
    except requests.RequestException as e:
        logger.error("Failed to send to support: %s", e)
        return False


def _put_to_hdfs(zip_path, config):
    """Upload the bundle to HDFS."""
    hdfs_base = config.get('hdfs_path', '/odpsc/diagnostics')
    filename = os.path.basename(zip_path)
    hdfs_dest = f"{hdfs_base}/{filename}"

    try:
        # Ensure HDFS directory exists
        subprocess.run(
            ['hdfs', 'dfs', '-mkdir', '-p', hdfs_base],
            capture_output=True, text=True, timeout=30,
        )
        # Upload file
        result = subprocess.run(
            ['hdfs', 'dfs', '-put', '-f', zip_path, hdfs_dest],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            logger.info("Bundle uploaded to HDFS: %s", hdfs_dest)
            return hdfs_dest
        else:
            logger.error("HDFS put failed: %s", result.stderr)
            return None
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.error("HDFS command failed: %s", e)
        return None


def _cleanup_data():
    """Clean up received agent data after processing."""
    if os.path.isdir(DATA_DIR):
        shutil.rmtree(DATA_DIR, ignore_errors=True)
        os.makedirs(DATA_DIR, exist_ok=True)
        logger.info("Cleaned up agent data directory")


def _scheduled_collect(app):
    """Execute a scheduled collection and send cycle."""
    with app.app_context():
        config = app.config['ODPSC']
        if not config.get('collection_enabled', True):
            logger.info("Scheduled collection skipped: collection disabled")
            return
        if not config.get('auto_send_enabled', True):
            logger.info("Scheduled collection skipped: auto-send disabled")
            return

        logger.info("Starting scheduled collection cycle")
        try:
            _trigger_agent_collection(config)
            time.sleep(10)
            aggregated = _aggregate_data()
            analysis = analyze_logs(aggregated.get('logs', {}))
            aggregated['analysis'] = analysis
            aggregated['analysis_report'] = generate_text_report(analysis)
            zip_path = _create_master_bundle(aggregated, config)
            _send_to_support(zip_path, config)
            _cleanup_data()
            logger.info("Scheduled collection cycle completed")
        except Exception as e:
            logger.exception("Scheduled collection failed: %s", e)


def _setup_scheduler(config, app=None):
    """Configure the scheduler based on send_frequency."""
    schedule.clear()
    frequency = config.get('send_frequency', 'weekly')

    if app is None:
        return

    if frequency == 'daily':
        schedule.every().day.at("00:00").do(_scheduled_collect, app)
        logger.info("Scheduler set to daily at 00:00")
    elif frequency == 'monthly':
        # Run on the 1st of each month
        schedule.every().day.at("00:00").do(
            lambda: _scheduled_collect(app) if datetime.now().day == 1 else None
        )
        logger.info("Scheduler set to monthly (1st of month at 00:00)")
    else:
        # Default: weekly on Sunday
        schedule.every().sunday.at("00:00").do(_scheduled_collect, app)
        logger.info("Scheduler set to weekly (Sunday at 00:00)")


def _run_scheduler():
    """Run the scheduler loop in a background thread."""
    while True:
        schedule.run_pending()
        time.sleep(60)


def write_pid():
    """Write the current PID to the PID file."""
    os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))


def remove_pid():
    """Remove the PID file."""
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)


def main():
    """Main entry point for the ODPSC Master."""
    config = load_config()
    app = create_app(config)

    # Setup scheduler
    _setup_scheduler(config, app)

    # Start scheduler in background thread
    scheduler_thread = threading.Thread(target=_run_scheduler, daemon=True)
    scheduler_thread.start()

    port = config.get('master_port', 8085)
    logger.info("Starting ODPSC Master on port %d", port)

    write_pid()
    try:
        app.run(host='0.0.0.0', port=port)
    finally:
        remove_pid()


if __name__ == '__main__':
    main()
