"""
ODPSC Master v2 - Flask server that receives agent bundles, deduplicates,
aggregates, analyzes, and stores/sends diagnostic data.

Uses SQLite for bundle tracking, AES-256-GCM encryption, bcrypt auth,
and gunicorn for production deployment.
"""

import hashlib
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import threading
import time
import zipfile
from datetime import datetime
from functools import wraps
from io import BytesIO

import bcrypt
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from flask import Flask, Response, jsonify, request, send_file

from analyzer import analyze_logs, generate_text_report

LOG_DIR = '/var/log/odpsc'
CONFIG_PATH = '/etc/odpsc/master_config.json'

MASTER_BASE_DIR = '/var/lib/odpsc/master'
BUNDLE_DIR = os.path.join(MASTER_BASE_DIR, 'bundles')
DB_DIR = os.path.join(MASTER_BASE_DIR, 'db')
DB_PATH = os.path.join(DB_DIR, 'bundles.db')
AGGREGATED_DIR = os.path.join(MASTER_BASE_DIR, 'aggregated')

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
    'hdfs_archive_enabled': False,
    'master_port': 8085,
    'admin_username': 'admin',
    'admin_password_hash': '',
    'api_key': '',
    'encryption_key': '',
    'max_upload_size_mb': 100,
    'max_bundle_size_mb': 500,
    'log_paths': ['/var/log/hadoop/*', '/var/log/hive/*', '/var/log/spark/*', '/var/log/yarn/*'],
    'ambari_server_url': 'http://localhost:8080',
    'cluster_name': 'cluster',
    'gunicorn_workers': 2,
}


class BundleStore:
    """SQLite-based bundle tracking with WAL mode for concurrent access."""

    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_conn()
        try:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS bundles (
                    bundle_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    filepath TEXT NOT NULL,
                    level TEXT DEFAULT 'L1',
                    size_bytes INTEGER DEFAULT 0,
                    received_at TEXT NOT NULL,
                    aggregated INTEGER DEFAULT 0,
                    aggregated_at TEXT
                )
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_bundles_aggregated
                ON bundles(aggregated)
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_bundles_received_at
                ON bundles(received_at)
            ''')
            conn.commit()
        finally:
            conn.close()

    def register_bundle(self, bundle_id, hostname, filename, filepath, level='L1', size_bytes=0):
        """Register a new bundle. Returns True if new, False if duplicate."""
        conn = self._get_conn()
        try:
            conn.execute(
                '''INSERT INTO bundles (bundle_id, hostname, filename, filepath, level,
                   size_bytes, received_at) VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (bundle_id, hostname, filename, filepath, level, size_bytes,
                 datetime.now(tz=None).isoformat()),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def is_duplicate(self, bundle_id):
        """Check if a bundle ID has already been received."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                'SELECT 1 FROM bundles WHERE bundle_id = ?', (bundle_id,)
            ).fetchone()
            return row is not None
        finally:
            conn.close()

    def get_pending_bundles(self):
        """Get bundles that have not yet been aggregated."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                'SELECT * FROM bundles WHERE aggregated = 0 ORDER BY received_at'
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def mark_aggregated(self, bundle_ids):
        """Mark bundles as aggregated."""
        conn = self._get_conn()
        try:
            now = datetime.now(tz=None).isoformat()
            conn.executemany(
                'UPDATE bundles SET aggregated = 1, aggregated_at = ? WHERE bundle_id = ?',
                [(now, bid) for bid in bundle_ids],
            )
            conn.commit()
        finally:
            conn.close()

    def get_all_bundles(self, limit=100, offset=0):
        """Get all bundles with pagination."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                'SELECT * FROM bundles ORDER BY received_at DESC LIMIT ? OFFSET ?',
                (limit, offset),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_bundle(self, bundle_id):
        """Get a single bundle by ID."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                'SELECT * FROM bundles WHERE bundle_id = ?', (bundle_id,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def cleanup_old(self, days=30):
        """Remove bundle records older than N days (does not delete files)."""
        conn = self._get_conn()
        try:
            cutoff = datetime.now(tz=None).isoformat()[:10]
            conn.execute(
                'DELETE FROM bundles WHERE received_at < date(?, ?)',
                (cutoff, f'-{days} days'),
            )
            conn.commit()
        finally:
            conn.close()

    def get_bundle_count(self):
        """Get total number of bundles."""
        conn = self._get_conn()
        try:
            row = conn.execute('SELECT COUNT(*) as cnt FROM bundles').fetchone()
            return row['cnt'] if row else 0
        finally:
            conn.close()


# Rate limiting: simple per-IP token bucket
_rate_limit_lock = threading.Lock()
_rate_limits = {}  # ip -> (tokens, last_refill_time)
RATE_LIMIT_TOKENS = 30
RATE_LIMIT_REFILL_SECONDS = 60


def _check_rate_limit(ip):
    """Check if a request from this IP is within rate limits. Returns True if allowed."""
    now = time.time()
    with _rate_limit_lock:
        if ip not in _rate_limits:
            _rate_limits[ip] = [RATE_LIMIT_TOKENS - 1, now]
            return True
        tokens, last_refill = _rate_limits[ip]
        elapsed = now - last_refill
        if elapsed >= RATE_LIMIT_REFILL_SECONDS:
            _rate_limits[ip] = [RATE_LIMIT_TOKENS - 1, now]
            return True
        if tokens > 0:
            _rate_limits[ip][0] -= 1
            return True
        return False


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


def hash_password(password):
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(password, password_hash):
    """Verify a password against a bcrypt hash."""
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except (ValueError, TypeError):
        return False


def derive_encryption_key(key_material):
    """Derive a 256-bit key from arbitrary key material using PBKDF2."""
    if isinstance(key_material, str):
        key_material = key_material.encode('utf-8')
    salt = b'odpsc-v2-salt'  # Fixed salt since key_material is already high-entropy
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(key_material)


def encrypt_bundle(zip_path, encryption_key):
    """
    Encrypt a bundle file using AES-256-GCM with PBKDF2-derived key.

    Returns path to encrypted file.
    """
    try:
        key = derive_encryption_key(encryption_key)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)

        with open(zip_path, 'rb') as f:
            data = f.read()

        encrypted = aesgcm.encrypt(nonce, data, None)
        encrypted_path = zip_path + '.enc'

        with open(encrypted_path, 'wb') as f:
            f.write(nonce + encrypted)

        os.remove(zip_path)
        logger.info("Encrypted bundle: %s", encrypted_path)
        return encrypted_path

    except Exception as e:
        logger.error("Encryption failed, keeping unencrypted bundle: %s", e)
        return zip_path


def decrypt_bundle(encrypted_path, encryption_key):
    """
    Decrypt a bundle file encrypted with AES-256-GCM.

    Returns decrypted data bytes.
    """
    key = derive_encryption_key(encryption_key)
    aesgcm = AESGCM(key)

    with open(encrypted_path, 'rb') as f:
        raw = f.read()

    nonce = raw[:12]
    ciphertext = raw[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


def create_app(config=None):
    """Create and configure the Flask application."""
    app = Flask(__name__)

    if config is None:
        config = load_config()
    app.config['ODPSC'] = config

    max_upload = config.get('max_upload_size_mb', 100) * 1024 * 1024
    app.config['MAX_CONTENT_LENGTH'] = max_upload

    # Ensure working directories exist
    for d in (BUNDLE_DIR, DB_DIR, AGGREGATED_DIR):
        os.makedirs(d, exist_ok=True)

    # Initialize bundle store (use module-level DB_PATH so monkeypatch works in tests)
    bundle_store = BundleStore(db_path=DB_PATH)
    app.config['BUNDLE_STORE'] = bundle_store

    def get_config():
        return app.config['ODPSC']

    def require_api_key(f):
        """Decorator for API key auth on agent upload endpoints."""
        @wraps(f)
        def decorated(*args, **kwargs):
            cfg = get_config()
            expected_key = cfg.get('api_key', '')
            if not expected_key:
                return f(*args, **kwargs)

            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                provided_key = auth_header[7:]
            else:
                provided_key = ''

            if provided_key != expected_key:
                return jsonify({'error': 'Invalid or missing API key'}), 401
            return f(*args, **kwargs)
        return decorated

    def require_auth(f):
        """Decorator for Basic Auth with bcrypt on management endpoints."""
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.authorization
            cfg = get_config()

            if not auth:
                return Response(
                    json.dumps({'error': 'Unauthorized'}),
                    status=401,
                    mimetype='application/json',
                    headers={'WWW-Authenticate': 'Basic realm="ODPSC"'},
                )

            username_ok = auth.username == cfg.get('admin_username', 'admin')
            password_hash = cfg.get('admin_password_hash', '')

            if password_hash:
                password_ok = verify_password(auth.password, password_hash)
            else:
                # Fallback: plaintext comparison (for backward compat / testing)
                password_ok = auth.password == cfg.get('admin_password', '')

            if not username_ok or not password_ok:
                return Response(
                    json.dumps({'error': 'Unauthorized'}),
                    status=401,
                    mimetype='application/json',
                    headers={'WWW-Authenticate': 'Basic realm="ODPSC"'},
                )
            return f(*args, **kwargs)
        return decorated

    # === v2 endpoints ===

    @app.route('/api/v2/bundles/upload', methods=['POST'])
    @require_api_key
    def upload_bundle_endpoint():
        """Receive a diagnostic bundle from an agent with deduplication."""
        # Rate limiting
        client_ip = request.remote_addr
        if not _check_rate_limit(client_ip):
            return jsonify({'error': 'Too many requests'}), 429

        if 'bundle' not in request.files:
            return jsonify({'error': 'No bundle file provided'}), 400

        bundle_file = request.files['bundle']
        if not bundle_file.filename:
            return jsonify({'error': 'Empty filename'}), 400

        bundle_id = request.headers.get('X-ODPSC-Bundle-ID', '')
        if not bundle_id:
            return jsonify({'error': 'Missing X-ODPSC-Bundle-ID header'}), 400

        # Dedup check
        store = app.config['BUNDLE_STORE']
        if store.is_duplicate(bundle_id):
            logger.info("Duplicate bundle received: %s", bundle_id)
            return jsonify({
                'status': 'duplicate',
                'bundle_id': bundle_id,
                'message': 'Bundle already received',
            })

        # Save to bundle directory
        timestamp = datetime.now(tz=None).strftime('%Y%m%d_%H%M%S')
        safe_name = f"agent_{timestamp}_{bundle_file.filename}"
        save_path = os.path.join(BUNDLE_DIR, safe_name)

        bundle_file.save(save_path)
        size_bytes = os.path.getsize(save_path)

        # Extract hostname and level from manifest if possible
        hostname = 'unknown'
        level = 'L1'
        try:
            with zipfile.ZipFile(save_path, 'r') as zf:
                if 'manifest.json' in zf.namelist():
                    manifest = json.loads(zf.read('manifest.json'))
                    hostname = manifest.get('hostname', 'unknown')
                    level = manifest.get('level', 'L1')
        except (zipfile.BadZipFile, json.JSONDecodeError, KeyError):
            pass

        store.register_bundle(bundle_id, hostname, safe_name, save_path, level, size_bytes)
        logger.info("Received agent bundle: %s (id=%s, host=%s)", save_path, bundle_id, hostname)

        return jsonify({
            'status': 'received',
            'bundle_id': bundle_id,
            'filename': safe_name,
        })

    @app.route('/api/v2/bundles', methods=['GET'])
    @require_auth
    def list_bundles():
        """List received bundles."""
        store = app.config['BUNDLE_STORE']
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        bundles = store.get_all_bundles(limit=limit, offset=offset)
        return jsonify({
            'bundles': bundles,
            'count': len(bundles),
            'total': store.get_bundle_count(),
        })

    @app.route('/api/v2/bundles/<bundle_id>', methods=['GET'])
    @require_auth
    def get_bundle(bundle_id):
        """Download a specific bundle."""
        store = app.config['BUNDLE_STORE']
        bundle = store.get_bundle(bundle_id)
        if not bundle:
            return jsonify({'error': 'Bundle not found'}), 404

        filepath = bundle['filepath']
        if not os.path.exists(filepath):
            return jsonify({'error': 'Bundle file not found on disk'}), 404

        return send_file(filepath, mimetype='application/zip',
                         as_attachment=True, download_name=bundle['filename'])

    @app.route('/api/v2/collect', methods=['POST'])
    @require_auth
    def manual_collect():
        """Trigger manual collection via Ambari custom command."""
        cfg = get_config()

        if not cfg.get('collection_enabled', True):
            return jsonify({'error': 'Collection is disabled'}), 403

        level = 'L1'
        send = False
        if request.is_json and request.json:
            level = request.json.get('level', 'L1')
            send = request.json.get('send', False)

        try:
            _trigger_agent_collection(cfg, level)
            return jsonify({
                'status': 'triggered',
                'level': level,
                'message': 'Collection triggered on agents via Ambari',
            })
        except Exception as e:
            logger.exception("Manual collection trigger failed: %s", e)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v2/aggregate', methods=['POST'])
    @require_auth
    def aggregate():
        """Trigger aggregation of pending bundles."""
        cfg = get_config()
        try:
            store = app.config['BUNDLE_STORE']
            result = _aggregate_bundles(store, cfg)
            return jsonify(result)
        except Exception as e:
            logger.exception("Aggregation failed: %s", e)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v2/config', methods=['GET'])
    @require_auth
    def get_configuration():
        """Return the current configuration (sensitive fields masked)."""
        cfg = get_config().copy()
        for key in ('support_token', 'admin_password', 'admin_password_hash',
                     'encryption_key', 'api_key'):
            if cfg.get(key):
                cfg[key] = '****MASKED****'
        return jsonify(cfg)

    @app.route('/api/v2/config', methods=['POST'])
    @require_auth
    def update_configuration():
        """Update configuration properties."""
        if not request.is_json:
            return jsonify({'error': 'JSON body required'}), 400

        updates = request.json
        cfg = get_config()

        updatable = {
            'collection_enabled', 'auto_send_enabled', 'send_frequency',
            'support_endpoint', 'support_token', 'hdfs_path',
            'hdfs_archive_enabled', 'log_paths',
            'admin_username', 'encryption_key',
            'log_retention_days', 'max_log_size_mb',
            'max_upload_size_mb', 'max_bundle_size_mb',
            'bundle_level',
        }

        applied = {}
        for key, value in updates.items():
            if key in updatable:
                cfg[key] = value
                applied[key] = value
            elif key == 'admin_password':
                cfg['admin_password_hash'] = hash_password(value)
                applied['admin_password'] = '****UPDATED****'

        if applied:
            app.config['ODPSC'] = cfg
            save_config(cfg)

        return jsonify({'status': 'updated', 'applied': list(applied.keys())})

    @app.route('/api/v2/status', methods=['GET'])
    @require_auth
    def get_status():
        """Return the current status of the ODPSC Master."""
        cfg = get_config()
        store = app.config['BUNDLE_STORE']

        return jsonify({
            'status': 'running',
            'version': '2.0',
            'collection_enabled': cfg.get('collection_enabled', True),
            'auto_send_enabled': cfg.get('auto_send_enabled', True),
            'send_frequency': cfg.get('send_frequency', 'weekly'),
            'hdfs_archive_enabled': cfg.get('hdfs_archive_enabled', False),
            'bundle_count': store.get_bundle_count(),
            'pending_bundles': len(store.get_pending_bundles()),
            'timestamp': datetime.now(tz=None).isoformat(),
        })

    return app


def _trigger_agent_collection(config, level='L1'):
    """Trigger agent collection via Ambari custom command API."""
    ambari_url = config.get('ambari_server_url', 'http://localhost:8080')
    cluster_name = config.get('cluster_name', 'cluster')

    try:
        url = f"{ambari_url}/api/v1/clusters/{cluster_name}/requests"
        payload = {
            "RequestInfo": {
                "context": f"ODPSC Agent Collection (Level {level})",
                "command": "COLLECT",
                "parameters/bundle_level": level,
            },
            "Requests/resource_filters": [{
                "service_name": "ODPSC",
                "component_name": "ODPSC_AGENT",
                "hosts": "",
            }],
        }
        resp = requests.post(url, json=payload, timeout=30)
        logger.info(
            "Triggered agent collection via Ambari (status %d, level %s)",
            resp.status_code, level,
        )
    except requests.RequestException as e:
        logger.warning(
            "Failed to trigger agents via Ambari: %s", e
        )


def _aggregate_bundles(store, config):
    """
    Aggregate pending bundles one at a time (streaming) into a master bundle.
    Respects max_bundle_size_mb to bound memory usage.
    """
    pending = store.get_pending_bundles()
    if not pending:
        return {'status': 'no_pending', 'message': 'No pending bundles to aggregate'}

    max_size = config.get('max_bundle_size_mb', 500) * 1024 * 1024
    os.makedirs(AGGREGATED_DIR, exist_ok=True)

    timestamp = datetime.now(tz=None).strftime('%Y%m%d_%H%M%S')
    output_filename = f'odpsc_bundle_{timestamp}.zip'
    output_path = os.path.join(AGGREGATED_DIR, output_filename)

    all_logs = {}
    all_metrics = []
    all_configs = {}
    all_system_info = []
    agent_count = 0
    aggregated_ids = []
    current_size = 0

    for bundle_info in pending:
        filepath = bundle_info['filepath']
        if not os.path.exists(filepath):
            logger.warning("Bundle file missing: %s", filepath)
            continue

        file_size = os.path.getsize(filepath)
        if current_size + file_size > max_size:
            logger.warning("Max bundle size reached, stopping aggregation")
            break

        try:
            with zipfile.ZipFile(filepath, 'r') as zf:
                for name in zf.namelist():
                    if name == 'manifest.json':
                        continue
                    content = zf.read(name).decode('utf-8', errors='replace')

                    if name.startswith('logs/'):
                        log_key = f"{bundle_info['hostname']}:{name}"
                        all_logs[log_key] = content
                    elif name == 'metrics.json':
                        try:
                            all_metrics.append(json.loads(content))
                        except json.JSONDecodeError:
                            pass
                    elif name.startswith('configs/'):
                        config_key = f"{bundle_info['hostname']}:{name}"
                        all_configs[config_key] = content
                    elif name == 'system_info.json':
                        try:
                            all_system_info.append(json.loads(content))
                        except json.JSONDecodeError:
                            pass

            agent_count += 1
            aggregated_ids.append(bundle_info['bundle_id'])
            current_size += file_size

        except zipfile.BadZipFile:
            logger.error("Bad zip file: %s", filepath)
            aggregated_ids.append(bundle_info['bundle_id'])

    # Run analysis on collected logs
    analysis = analyze_logs(all_logs)
    analysis_report = generate_text_report(analysis)

    # Create the aggregated bundle
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for key, content in all_logs.items():
            safe_key = key.replace(':', '_').replace('/', '_')
            zf.writestr(f'logs/{safe_key}', content)

        zf.writestr('metrics.json', json.dumps(all_metrics, indent=2))

        for key, content in all_configs.items():
            safe_key = key.replace(':', '_').replace('/', '_')
            zf.writestr(f'configs/{safe_key}', content)

        zf.writestr('system_info.json', json.dumps(all_system_info, indent=2))
        zf.writestr('analysis.json', json.dumps(analysis, indent=2))
        zf.writestr('analysis_report.txt', analysis_report)

        metadata = {
            'created': timestamp,
            'agent_count': agent_count,
            'bundle_ids': aggregated_ids,
            'odpsc_version': '2.0',
        }
        zf.writestr('metadata.json', json.dumps(metadata, indent=2))

    # Encrypt if key is configured
    encryption_key = config.get('encryption_key')
    if encryption_key:
        output_path = encrypt_bundle(output_path, encryption_key)

    # Mark bundles as aggregated
    store.mark_aggregated(aggregated_ids)

    # Optionally archive to HDFS
    hdfs_path = None
    if config.get('hdfs_archive_enabled', False):
        hdfs_path = _put_to_hdfs(output_path, config)

    logger.info(
        "Aggregated %d bundles into %s (%d logs, %d metrics)",
        agent_count, output_path, len(all_logs), len(all_metrics),
    )

    return {
        'status': 'aggregated',
        'output': output_path,
        'agent_count': agent_count,
        'bundles_processed': len(aggregated_ids),
        'hdfs_path': hdfs_path,
    }


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
    """Upload the bundle to HDFS (optional archive)."""
    hdfs_base = config.get('hdfs_path', '/odpsc/diagnostics')
    filename = os.path.basename(zip_path)
    hdfs_dest = f"{hdfs_base}/{filename}"

    try:
        subprocess.run(
            ['hdfs', 'dfs', '-mkdir', '-p', hdfs_base],
            capture_output=True, text=True, timeout=30,
        )
        result = subprocess.run(
            ['hdfs', 'dfs', '-put', '-f', zip_path, hdfs_dest],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            logger.info("Bundle archived to HDFS: %s", hdfs_dest)
            return hdfs_dest
        else:
            logger.error("HDFS put failed: %s", result.stderr)
            return None
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.error("HDFS command failed: %s", e)
        return None


def main():
    """Main entry point for standalone execution (use wsgi.py for production)."""
    config = load_config()
    app = create_app(config)

    port = config.get('master_port', 8085)
    logger.info("Starting ODPSC Master on port %d (dev mode)", port)
    app.run(host='0.0.0.0', port=port)


if __name__ == '__main__':
    main()
