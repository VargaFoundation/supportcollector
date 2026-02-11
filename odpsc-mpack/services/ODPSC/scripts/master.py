"""
Ambari lifecycle script for the ODPSC Master component.
Handles install, configure, start, stop, and status commands from Ambari.
"""

import os
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


class OdpscMaster(Script):

    def install(self, env):
        Logger.info("Installing ODPSC Master")
        import params  # noqa: Ambari injects params

        # Create directories
        Directory(RESOURCES_DIR, create_parents=True, owner='root', group='root')
        Directory(CONFIG_DIR, create_parents=True, owner='root', group='root')
        Directory(LOG_DIR, create_parents=True, owner='root', group='root')
        Directory('/var/run/odpsc', create_parents=True, owner='root', group='root')

        # Install Python dependencies
        Execute('pip3 install flask schedule requests psutil cryptography')

        # Copy resources
        service_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        resources_src = os.path.join(service_dir, 'resources')

        for filename in ('odpsc_master.py', 'analyzer.py', 'requirements.txt'):
            src = os.path.join(resources_src, filename)
            dst = os.path.join(RESOURCES_DIR, filename)
            if os.path.exists(src):
                Execute(f'cp {src} {dst}')

        Logger.info("ODPSC Master installed successfully")

    def configure(self, env):
        Logger.info("Configuring ODPSC Master")
        import params  # noqa

        config = self.get_config()
        odpsc_site = config['configurations'].get('odpsc-site', {})

        # Generate master_config.json from Ambari properties
        import json
        master_config = {
            'collection_enabled': odpsc_site.get('collection_enabled', 'true').lower() == 'true',
            'auto_send_enabled': odpsc_site.get('auto_send_enabled', 'true').lower() == 'true',
            'send_frequency': odpsc_site.get('send_frequency', 'weekly'),
            'support_endpoint': odpsc_site.get('support_endpoint', 'https://support.odp.com/upload'),
            'support_token': odpsc_site.get('support_token', ''),
            'hdfs_path': odpsc_site.get('hdfs_path', '/odpsc/diagnostics'),
            'master_port': int(odpsc_site.get('master_port', 8085)),
            'admin_username': odpsc_site.get('admin_username', 'admin'),
            'admin_password': odpsc_site.get('admin_password', 'admin'),
            'encryption_key': odpsc_site.get('encryption_key', ''),
            'log_paths': json.loads(odpsc_site.get('log_paths', '[]')),
            'ambari_server_url': odpsc_site.get('ambari_server_url', 'http://localhost:8080'),
            'cluster_name': odpsc_site.get('cluster_name', 'cluster'),
        }

        config_path = os.path.join(CONFIG_DIR, 'master_config.json')
        File(config_path, content=json.dumps(master_config, indent=2), owner='root', group='root', mode=0o600)

        Logger.info("ODPSC Master configured")

    def start(self, env):
        Logger.info("Starting ODPSC Master")
        self.configure(env)

        Execute(
            f'nohup python3 {MASTER_SCRIPT} '
            f'>> {LOG_DIR}/master.log 2>&1 &',
            user='root',
        )

        # Wait for PID file to appear
        import time
        for _ in range(10):
            if os.path.exists(PID_FILE):
                break
            time.sleep(1)

        Logger.info("ODPSC Master started")

    def stop(self, env):
        Logger.info("Stopping ODPSC Master")

        if os.path.exists(PID_FILE):
            try:
                with open(PID_FILE, 'r') as f:
                    pid = int(f.read().strip())
                os.kill(pid, signal.SIGTERM)
                Logger.info(f"Sent SIGTERM to PID {pid}")
            except (ValueError, ProcessLookupError, IOError) as e:
                Logger.error(f"Failed to stop master: {e}")
            finally:
                if os.path.exists(PID_FILE):
                    os.remove(PID_FILE)
        else:
            Logger.info("PID file not found, master may not be running")

    def status(self, env):
        """Check if the master process is running."""
        if not os.path.exists(PID_FILE):
            raise ComponentIsNotRunning()

        try:
            with open(PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)  # Check if process exists
        except (ValueError, ProcessLookupError, IOError):
            raise ComponentIsNotRunning()


class ComponentIsNotRunning(Exception):
    pass


if __name__ == '__main__':
    OdpscMaster().execute()
