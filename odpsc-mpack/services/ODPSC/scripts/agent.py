"""
Ambari lifecycle script for the ODPSC Agent v2 component.
Handles install, configure, start, stop, status, and COLLECT custom command.
"""

import os
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
AGENT_SCRIPT = os.path.join(RESOURCES_DIR, 'odpsc_agent.py')
CRON_FILE = '/etc/cron.d/odpsc-agent'
ODPSC_USER = 'odpsc'

# Agent staging directories
AGENT_BASE_DIR = '/var/lib/odpsc/agent'
OUTBOX_DIR = os.path.join(AGENT_BASE_DIR, 'outbox')
SENT_DIR = os.path.join(AGENT_BASE_DIR, 'sent')
FAILED_DIR = os.path.join(AGENT_BASE_DIR, 'failed')


class OdpscAgent(Script):

    def install(self, env):
        Logger.info("Installing ODPSC Agent v2")

        # Create service user
        try:
            Execute(f'id -u {ODPSC_USER} || useradd -r -s /sbin/nologin {ODPSC_USER}')
        except Exception:
            Logger.info("Service user creation skipped (may already exist)")

        # Create directories
        Directory(RESOURCES_DIR, create_parents=True, owner=ODPSC_USER, group=ODPSC_USER)
        Directory(CONFIG_DIR, create_parents=True, owner=ODPSC_USER, group=ODPSC_USER)
        Directory(LOG_DIR, create_parents=True, owner=ODPSC_USER, group=ODPSC_USER)
        Directory(AGENT_BASE_DIR, create_parents=True, owner=ODPSC_USER, group=ODPSC_USER)
        Directory(OUTBOX_DIR, create_parents=True, owner=ODPSC_USER, group=ODPSC_USER)
        Directory(SENT_DIR, create_parents=True, owner=ODPSC_USER, group=ODPSC_USER)
        Directory(FAILED_DIR, create_parents=True, owner=ODPSC_USER, group=ODPSC_USER)

        # Install Python dependencies
        Execute('pip3 install requests psutil')

        # Copy resources
        service_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        resources_src = os.path.join(service_dir, 'resources')

        for filename in ('odpsc_agent.py', 'requirements.txt'):
            src = os.path.join(resources_src, filename)
            dst = os.path.join(RESOURCES_DIR, filename)
            if os.path.exists(src):
                Execute(f'cp {src} {dst}')

        Logger.info("ODPSC Agent v2 installed successfully")

    def configure(self, env):
        Logger.info("Configuring ODPSC Agent v2")

        config = self.get_config()
        odpsc_site = config['configurations'].get('odpsc-site', {})

        # Determine master host from Ambari topology
        master_host = 'localhost'
        try:
            cluster_host_info = config.get('clusterHostInfo', {})
            master_hosts = cluster_host_info.get('odpsc_master_hosts', [])
            if master_hosts:
                master_host = master_hosts[0]
        except (KeyError, IndexError):
            pass

        master_port = odpsc_site.get('master_port', '8085')
        tls_enabled = odpsc_site.get('tls_enabled', 'false').lower() == 'true'
        scheme = 'https' if tls_enabled else 'http'

        import json
        agent_config = {
            'collection_enabled': odpsc_site.get('collection_enabled', 'true').lower() == 'true',
            'master_url': f'{scheme}://{master_host}:{master_port}',
            'api_key': odpsc_site.get('api_key', ''),
            'bundle_level': odpsc_site.get('bundle_level', 'L1'),
            'log_paths': json.loads(odpsc_site.get('log_paths', '[]')),
            'config_paths': ['/etc/hadoop/conf/*'],
            'max_log_size_mb': int(odpsc_site.get('max_log_size_mb', 1)),
            'log_retention_days': int(odpsc_site.get('log_retention_days', 7)),
            'ambari_server_url': odpsc_site.get('ambari_server_url', 'http://localhost:8080'),
            'cluster_name': odpsc_site.get('cluster_name', 'cluster'),
        }

        config_path = os.path.join(CONFIG_DIR, 'agent_config.json')
        File(config_path, content=json.dumps(agent_config, indent=2),
             owner=ODPSC_USER, group=ODPSC_USER, mode=0o600)

        # Setup collection cron job based on frequency
        frequency = odpsc_site.get('send_frequency', 'weekly')
        cron_schedule = _get_cron_schedule(frequency)

        cron_content = (
            f"# ODPSC Agent v2 collection schedule\n"
            f"{cron_schedule} {ODPSC_USER} python3 {AGENT_SCRIPT} --collect --cleanup "
            f">> {LOG_DIR}/agent.log 2>&1\n"
            f"# Retry pending uploads every 15 minutes\n"
            f"*/15 * * * * {ODPSC_USER} python3 {AGENT_SCRIPT} --retry "
            f">> {LOG_DIR}/agent.log 2>&1\n"
        )
        File(CRON_FILE, content=cron_content, owner='root', group='root', mode=0o644)

        Logger.info("ODPSC Agent v2 configured")

    def start(self, env):
        Logger.info("Starting ODPSC Agent v2")
        self.configure(env)

        # Run an initial collection
        Execute(
            f'python3 {AGENT_SCRIPT} --collect >> {LOG_DIR}/agent.log 2>&1',
            user=ODPSC_USER,
        )

        Logger.info("ODPSC Agent v2 started (initial collection triggered)")

    def stop(self, env):
        Logger.info("Stopping ODPSC Agent v2")

        # Remove cron job
        if os.path.exists(CRON_FILE):
            os.remove(CRON_FILE)
            Logger.info("Removed cron job")

    def status(self, env):
        """Check if the agent cron job is installed."""
        if not os.path.exists(CRON_FILE):
            raise ComponentIsNotRunning()

    def collect(self, env):
        """Custom command: COLLECT - triggered via Ambari."""
        Logger.info("ODPSC Agent COLLECT command received")
        self.configure(env)

        config = self.get_config()
        odpsc_site = config['configurations'].get('odpsc-site', {})
        level = odpsc_site.get('bundle_level', 'L1')

        # Check if parameters override the level
        try:
            params = config.get('commandParams', {})
            if params.get('bundle_level'):
                level = params['bundle_level']
        except (KeyError, AttributeError):
            pass

        Execute(
            f'python3 {AGENT_SCRIPT} --collect --level {level} '
            f'>> {LOG_DIR}/agent.log 2>&1',
            user=ODPSC_USER,
        )
        Logger.info("ODPSC Agent COLLECT completed (level=%s)" % level)


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
    OdpscAgent().execute()
