"""
Ambari lifecycle script for the ODPSC Master v2 component.
Handles install, configure, start, stop, status, and AGGREGATE custom command.
Uses gunicorn for production deployment.
"""

import os
import secrets
import signal
import subprocess
import sys

# Ambari resource_management imports
try:
    from resource_management.core.resources.system import Execute, File, Directory
    from resource_management.libraries.script.script import Script
    from resource_management.core.logger import Logger
except ImportError:
    # Fallback for testing outside Ambari
    class Script:
        def install(self, env): pass
        def configure(self, env): pass
        def start(self, env): pass
        def stop(self, env): pass
        def status(self, env): pass
        def get_config(self): return {'configurations': {'odpsc-site': {}}}

    class Logger:
        @staticmethod
        def info(msg): print(f"[INFO] {msg}")
        @staticmethod
        def error(msg): print(f"[ERROR] {msg}")

    def Execute(cmd, **kwargs): subprocess.call(cmd, shell=True)
    def Directory(path, **kwargs): os.makedirs(path, exist_ok=True)
    def File(path, **kwargs):
        content = kwargs.get('content', '')
        with open(path, 'w') as f:
            f.write(content)


RESOURCES_DIR = '/usr/lib/odpsc'
CONFIG_DIR = '/etc/odpsc'
LOG_DIR = '/var/log/odpsc'
PID_FILE = '/var/run/odpsc/master.pid'
MASTER_SCRIPT = os.path.join(RESOURCES_DIR, 'odpsc_master.py')
WSGI_SCRIPT = os.path.join(RESOURCES_DIR, 'wsgi.py')
CRON_FILE = '/etc/cron.d/odpsc-master'
ODPSC_USER = 'odpsc'

# Master storage directories
MASTER_BASE_DIR = '/var/lib/odpsc/master'
BUNDLE_DIR = os.path.join(MASTER_BASE_DIR, 'bundles')
DB_DIR = os.path.join(MASTER_BASE_DIR, 'db')
AGGREGATED_DIR = os.path.join(MASTER_BASE_DIR, 'aggregated')


class OdpscMaster(Script):

    def install(self, env):
        Logger.info("Installing ODPSC Master v2")

        # Create service user
        try:
            Execute(f'id -u {ODPSC_USER} || useradd -r -s /sbin/nologin {ODPSC_USER}')
        except Exception:
            Logger.info("Service user creation skipped (may already exist)")

        # Create directories
        Directory(RESOURCES_DIR, create_parents=True, owner=ODPSC_USER, group=ODPSC_USER)
        Directory(CONFIG_DIR, create_parents=True, owner=ODPSC_USER, group=ODPSC_USER)
        Directory(LOG_DIR, create_parents=True, owner=ODPSC_USER, group=ODPSC_USER)
        Directory('/var/run/odpsc', create_parents=True, owner=ODPSC_USER, group=ODPSC_USER)
        Directory(MASTER_BASE_DIR, create_parents=True, owner=ODPSC_USER, group=ODPSC_USER)
        Directory(BUNDLE_DIR, create_parents=True, owner=ODPSC_USER, group=ODPSC_USER)
        Directory(DB_DIR, create_parents=True, owner=ODPSC_USER, group=ODPSC_USER)
        Directory(AGGREGATED_DIR, create_parents=True, owner=ODPSC_USER, group=ODPSC_USER)

        # Install Python dependencies
        Execute('pip3 install flask requests psutil cryptography gunicorn bcrypt')

        # Copy resources
        service_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        resources_src = os.path.join(service_dir, 'resources')

        for filename in ('odpsc_master.py', 'analyzer.py', 'wsgi.py', 'audit.py', 'requirements.txt'):
            src = os.path.join(resources_src, filename)
            dst = os.path.join(RESOURCES_DIR, filename)
            if os.path.exists(src):
                Execute(f'cp {src} {dst}')

        # Generate API key if not set
        self._ensure_api_key(env)

        # Generate cluster_id if not set
        self._ensure_cluster_id(env)

        # Generate bcrypt password hash for admin
        self._ensure_password_hash(env)

        Logger.info("ODPSC Master v2 installed successfully")

    def _ensure_cluster_id(self, env):
        """Generate a unique cluster ID if not already set."""
        config = self.get_config()
        odpsc_site = config['configurations'].get('odpsc-site', {})
        if not odpsc_site.get('cluster_id'):
            cluster_id = secrets.token_hex(32)
            Logger.info("Generated new cluster ID: %s" % cluster_id[:16] + "...")
            id_file = os.path.join(CONFIG_DIR, 'cluster_id')
            File(id_file, content=cluster_id, owner=ODPSC_USER, group=ODPSC_USER, mode=0o644)

    def _ensure_api_key(self, env):
        """Generate API key if not already set."""
        config = self.get_config()
        odpsc_site = config['configurations'].get('odpsc-site', {})
        if not odpsc_site.get('api_key'):
            api_key = secrets.token_urlsafe(32)
            Logger.info("Generated new API key for agent authentication")
            # Store in config file (Ambari will persist via config update)
            key_file = os.path.join(CONFIG_DIR, 'api_key')
            File(key_file, content=api_key, owner=ODPSC_USER, group=ODPSC_USER, mode=0o600)

    def _ensure_password_hash(self, env):
        """Generate bcrypt hash for admin password during install."""
        config = self.get_config()
        odpsc_site = config['configurations'].get('odpsc-site', {})
        password = odpsc_site.get('admin_password', '')
        if password:
            try:
                import bcrypt as _bcrypt
                password_hash = _bcrypt.hashpw(
                    password.encode('utf-8'),
                    _bcrypt.gensalt(),
                ).decode('utf-8')
                Logger.info("Generated bcrypt hash for admin password")
                return password_hash
            except ImportError:
                Logger.error("bcrypt not available, password hashing skipped")
        return ''

    def configure(self, env):
        Logger.info("Configuring ODPSC Master v2")

        config = self.get_config()
        odpsc_site = config['configurations'].get('odpsc-site', {})

        # Read or generate API key
        api_key = odpsc_site.get('api_key', '')
        if not api_key:
            key_file = os.path.join(CONFIG_DIR, 'api_key')
            if os.path.exists(key_file):
                with open(key_file, 'r') as f:
                    api_key = f.read().strip()

        # Read or generate cluster_id
        cluster_id = odpsc_site.get('cluster_id', '')
        if not cluster_id:
            id_file = os.path.join(CONFIG_DIR, 'cluster_id')
            if os.path.exists(id_file):
                with open(id_file, 'r') as f:
                    cluster_id = f.read().strip()

        # Generate password hash
        password_hash = self._ensure_password_hash(env)

        import json
        master_config = {
            'collection_enabled': odpsc_site.get('collection_enabled', 'true').lower() == 'true',
            'auto_send_enabled': odpsc_site.get('auto_send_enabled', 'true').lower() == 'true',
            'send_frequency': odpsc_site.get('send_frequency', 'weekly'),
            'support_endpoint': odpsc_site.get('support_endpoint', 'https://support.odp.com/upload'),
            'support_token': odpsc_site.get('support_token', ''),
            'hdfs_path': odpsc_site.get('hdfs_path', '/odpsc/diagnostics'),
            'hdfs_archive_enabled': odpsc_site.get('hdfs_archive_enabled', 'false').lower() == 'true',
            'master_port': int(odpsc_site.get('master_port', 8085)),
            'admin_username': odpsc_site.get('admin_username', 'admin'),
            'admin_password_hash': password_hash,
            'api_key': api_key,
            'encryption_key': odpsc_site.get('encryption_key', ''),
            'max_upload_size_mb': int(odpsc_site.get('max_upload_size_mb', 100)),
            'max_bundle_size_mb': int(odpsc_site.get('max_bundle_size_mb', 500)),
            'log_paths': json.loads(odpsc_site.get('log_paths', '[]')),
            'ambari_server_url': odpsc_site.get('ambari_server_url', 'http://localhost:8080'),
            'cluster_name': odpsc_site.get('cluster_name', 'cluster'),
            'gunicorn_workers': int(odpsc_site.get('gunicorn_workers', 2)),
            'bundle_level': odpsc_site.get('bundle_level', 'L1'),
            'cluster_id': cluster_id,
            'audit_enabled': odpsc_site.get('audit_enabled', 'false').lower() == 'true',
        }

        config_path = os.path.join(CONFIG_DIR, 'master_config.json')
        File(config_path, content=json.dumps(master_config, indent=2),
             owner=ODPSC_USER, group=ODPSC_USER, mode=0o600)

        # Setup cron for scheduled aggregation and send
        frequency = odpsc_site.get('send_frequency', 'weekly')
        cron_schedule = _get_cron_schedule(frequency)

        cron_content = (
            f"# ODPSC Master v2 aggregation schedule\n"
            f"{cron_schedule} {ODPSC_USER} "
            f"curl -s -u admin:admin -X POST http://localhost:{odpsc_site.get('master_port', 8085)}"
            f"/api/v2/aggregate >> {LOG_DIR}/master_cron.log 2>&1\n"
        )
        File(CRON_FILE, content=cron_content, owner='root', group='root', mode=0o644)

        Logger.info("ODPSC Master v2 configured")

    def start(self, env):
        Logger.info("Starting ODPSC Master v2")
        self.configure(env)

        config = self.get_config()
        odpsc_site = config['configurations'].get('odpsc-site', {})

        port = odpsc_site.get('master_port', '8085')
        workers = odpsc_site.get('gunicorn_workers', '2')
        tls_enabled = odpsc_site.get('tls_enabled', 'false').lower() == 'true'

        gunicorn_cmd = (
            f'gunicorn '
            f'--chdir {RESOURCES_DIR} '
            f'--bind 0.0.0.0:{port} '
            f'--workers {workers} '
            f'--pid {PID_FILE} '
            f'--access-logfile {LOG_DIR}/master_access.log '
            f'--error-logfile {LOG_DIR}/master_error.log '
            f'--daemon '
        )

        if tls_enabled:
            cert = odpsc_site.get('tls_cert_path', '')
            key = odpsc_site.get('tls_key_path', '')
            if cert and key:
                gunicorn_cmd += f'--certfile {cert} --keyfile {key} '

        gunicorn_cmd += 'wsgi:application'

        Execute(gunicorn_cmd, user=ODPSC_USER)

        # Wait for PID file to appear
        import time
        for _ in range(10):
            if os.path.exists(PID_FILE):
                break
            time.sleep(1)

        Logger.info("ODPSC Master v2 started (gunicorn)")

    def stop(self, env):
        Logger.info("Stopping ODPSC Master v2")

        if os.path.exists(PID_FILE):
            try:
                with open(PID_FILE, 'r') as f:
                    pid = int(f.read().strip())
                os.kill(pid, signal.SIGTERM)
                Logger.info(f"Sent SIGTERM to gunicorn master PID {pid}")
            except (ValueError, ProcessLookupError, IOError) as e:
                Logger.error(f"Failed to stop master: {e}")
            finally:
                if os.path.exists(PID_FILE):
                    os.remove(PID_FILE)
        else:
            Logger.info("PID file not found, master may not be running")

        # Remove cron job
        if os.path.exists(CRON_FILE):
            os.remove(CRON_FILE)

    def status(self, env):
        """Check if the master process is running."""
        if not os.path.exists(PID_FILE):
            raise ComponentIsNotRunning()

        try:
            with open(PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
        except (ValueError, ProcessLookupError, IOError):
            raise ComponentIsNotRunning()

    def aggregate(self, env):
        """Custom command: AGGREGATE - trigger bundle aggregation."""
        Logger.info("ODPSC Master AGGREGATE command received")
        self.configure(env)

        config = self.get_config()
        odpsc_site = config['configurations'].get('odpsc-site', {})
        port = odpsc_site.get('master_port', '8085')

        Execute(
            f'curl -s -X POST http://localhost:{port}/api/v2/aggregate '
            f'-u admin:admin >> {LOG_DIR}/master.log 2>&1',
        )
        Logger.info("ODPSC Master AGGREGATE completed")


class ComponentIsNotRunning(Exception):
    pass


def _get_cron_schedule(frequency):
    """Convert frequency string to cron schedule."""
    schedules = {
        'daily': '0 0 * * *',
        'weekly': '0 0 * * 0',
        'monthly': '0 0 1 * *',
    }
    return schedules.get(frequency, '0 0 * * 0')


if __name__ == '__main__':
    OdpscMaster().execute()
