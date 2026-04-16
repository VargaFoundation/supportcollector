"""
ODPSC Audit Module v2.1 - Tracks all bundle operations for transparency.
Disabled by default; when enabled, logs every bundle receive, aggregate, and send event.
"""

import json
import os
import sqlite3
import zipfile
from datetime import datetime


class AuditStore:
    """SQLite-backed audit event store."""

    def __init__(self, db_path):
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
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    bundle_id TEXT,
                    cluster_id TEXT,
                    hostname TEXT,
                    direction TEXT,
                    destination TEXT,
                    size_bytes INTEGER DEFAULT 0,
                    content_summary TEXT,
                    details TEXT
                )
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_events(timestamp)
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_bundle_id
                ON audit_events(bundle_id)
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_event_type
                ON audit_events(event_type)
            ''')
            conn.commit()
        finally:
            conn.close()

    def log_event(self, event_type, bundle_id='', cluster_id='', hostname='',
                  direction='', destination='', size_bytes=0, content_summary='',
                  details=''):
        """Log an audit event."""
        conn = self._get_conn()
        try:
            conn.execute(
                '''INSERT INTO audit_events
                   (timestamp, event_type, bundle_id, cluster_id, hostname,
                    direction, destination, size_bytes, content_summary, details)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (datetime.now(tz=None).isoformat(), event_type, bundle_id,
                 cluster_id, hostname, direction, destination, size_bytes,
                 content_summary, details),
            )
            conn.commit()
        finally:
            conn.close()

    def get_events(self, limit=100, offset=0, event_type=None):
        """Get audit events with pagination and optional filtering."""
        conn = self._get_conn()
        try:
            if event_type:
                rows = conn.execute(
                    '''SELECT * FROM audit_events WHERE event_type = ?
                       ORDER BY timestamp DESC LIMIT ? OFFSET ?''',
                    (event_type, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    '''SELECT * FROM audit_events
                       ORDER BY timestamp DESC LIMIT ? OFFSET ?''',
                    (limit, offset),
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_events_for_bundle(self, bundle_id):
        """Get all audit events for a specific bundle."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                '''SELECT * FROM audit_events WHERE bundle_id = ?
                   ORDER BY timestamp DESC''',
                (bundle_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_event_count(self, event_type=None):
        """Get total count of audit events."""
        conn = self._get_conn()
        try:
            if event_type:
                row = conn.execute(
                    'SELECT COUNT(*) as cnt FROM audit_events WHERE event_type = ?',
                    (event_type,),
                ).fetchone()
            else:
                row = conn.execute(
                    'SELECT COUNT(*) as cnt FROM audit_events',
                ).fetchone()
            return row['cnt'] if row else 0
        finally:
            conn.close()

    def cleanup_old(self, days=90):
        """Remove audit events older than N days."""
        conn = self._get_conn()
        try:
            cutoff = datetime.now(tz=None).isoformat()[:10]
            conn.execute(
                'DELETE FROM audit_events WHERE timestamp < date(?, ?)',
                (cutoff, f'-{days} days'),
            )
            conn.commit()
        finally:
            conn.close()


def is_audit_enabled(config):
    """Check if audit is enabled in the configuration."""
    return config.get('audit_enabled', False)


def audit_event(app, event_type, **kwargs):
    """Log an audit event if audit is enabled."""
    config = app.config.get('ODPSC', {})
    if not is_audit_enabled(config):
        return

    audit_store = app.config.get('AUDIT_STORE')
    if audit_store is None:
        return

    audit_store.log_event(event_type, **kwargs)


def generate_content_summary(zip_path):
    """Generate a summary of ZIP contents for audit transparency."""
    try:
        entries = []
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for info in zf.infolist():
                entries.append({
                    'filename': info.filename,
                    'size': info.file_size,
                    'compress_size': info.compress_size,
                })
        return json.dumps(entries)
    except (zipfile.BadZipFile, IOError, OSError):
        return '[]'
