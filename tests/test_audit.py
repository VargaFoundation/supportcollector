"""
Tests for the ODPSC Audit Module v2.1.
"""

import json
import os
import tempfile
import zipfile
from io import BytesIO

import pytest

from audit import AuditStore, audit_event, generate_content_summary, is_audit_enabled


class TestAuditStore:
    """Tests for AuditStore SQLite CRUD operations."""

    def test_create_audit_store(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'audit.db')
        store = AuditStore(db_path)
        assert os.path.exists(db_path)

    def test_log_event(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'audit.db')
        store = AuditStore(db_path)
        store.log_event(
            'bundle_received',
            bundle_id='bid-001',
            cluster_id='cid-001',
            hostname='node1',
            direction='inbound',
            size_bytes=1024,
        )
        events = store.get_events()
        assert len(events) == 1
        assert events[0]['event_type'] == 'bundle_received'
        assert events[0]['bundle_id'] == 'bid-001'
        assert events[0]['cluster_id'] == 'cid-001'
        assert events[0]['hostname'] == 'node1'
        assert events[0]['size_bytes'] == 1024

    def test_get_events_pagination(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'audit.db')
        store = AuditStore(db_path)
        for i in range(10):
            store.log_event('bundle_received', bundle_id=f'bid-{i:03d}')

        page1 = store.get_events(limit=5, offset=0)
        page2 = store.get_events(limit=5, offset=5)
        assert len(page1) == 5
        assert len(page2) == 5
        # No overlap
        ids1 = {e['bundle_id'] for e in page1}
        ids2 = {e['bundle_id'] for e in page2}
        assert ids1.isdisjoint(ids2)

    def test_get_events_by_type(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'audit.db')
        store = AuditStore(db_path)
        store.log_event('bundle_received', bundle_id='bid-001')
        store.log_event('bundle_aggregated', bundle_id='bid-002')
        store.log_event('bundle_sent', bundle_id='bid-003')

        received = store.get_events(event_type='bundle_received')
        assert len(received) == 1
        assert received[0]['event_type'] == 'bundle_received'

        aggregated = store.get_events(event_type='bundle_aggregated')
        assert len(aggregated) == 1

    def test_get_events_for_bundle(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'audit.db')
        store = AuditStore(db_path)
        store.log_event('bundle_received', bundle_id='bid-001')
        store.log_event('bundle_aggregated', bundle_id='bid-001')
        store.log_event('bundle_received', bundle_id='bid-002')

        events = store.get_events_for_bundle('bid-001')
        assert len(events) == 2
        for e in events:
            assert e['bundle_id'] == 'bid-001'

    def test_get_event_count(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'audit.db')
        store = AuditStore(db_path)
        assert store.get_event_count() == 0

        store.log_event('bundle_received', bundle_id='bid-001')
        store.log_event('bundle_received', bundle_id='bid-002')
        store.log_event('bundle_aggregated', bundle_id='bid-003')

        assert store.get_event_count() == 3
        assert store.get_event_count(event_type='bundle_received') == 2
        assert store.get_event_count(event_type='bundle_aggregated') == 1

    def test_cleanup_old(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'audit.db')
        store = AuditStore(db_path)
        store.log_event('bundle_received', bundle_id='bid-001')
        # cleanup_old with 0 days should not crash
        store.cleanup_old(days=0)
        assert store.get_event_count() >= 0

    def test_event_with_content_summary(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'audit.db')
        store = AuditStore(db_path)
        summary = json.dumps([{'filename': 'manifest.json', 'size': 100}])
        store.log_event(
            'bundle_received',
            bundle_id='bid-001',
            content_summary=summary,
        )
        events = store.get_events()
        assert len(events) == 1
        assert events[0]['content_summary'] == summary

    def test_event_with_details(self, tmp_dir):
        db_path = os.path.join(tmp_dir, 'audit.db')
        store = AuditStore(db_path)
        details = json.dumps({'agent_count': 3, 'bundles_processed': 5})
        store.log_event(
            'bundle_aggregated',
            bundle_id='bid-001',
            details=details,
        )
        events = store.get_events()
        assert events[0]['details'] == details


class TestAuditEnabled:
    """Tests for audit when enabled."""

    def test_is_audit_enabled_true(self):
        assert is_audit_enabled({'audit_enabled': True}) is True

    def test_is_audit_enabled_false(self):
        assert is_audit_enabled({'audit_enabled': False}) is False

    def test_is_audit_enabled_default(self):
        assert is_audit_enabled({}) is False

    def test_audit_event_logs_when_enabled(self, tmp_dir):
        from flask import Flask
        app = Flask(__name__)
        db_path = os.path.join(tmp_dir, 'audit.db')
        store = AuditStore(db_path)
        app.config['ODPSC'] = {'audit_enabled': True}
        app.config['AUDIT_STORE'] = store

        audit_event(app, 'bundle_received', bundle_id='bid-test')
        events = store.get_events()
        assert len(events) == 1
        assert events[0]['bundle_id'] == 'bid-test'


class TestAuditDisabled:
    """Tests for audit when disabled (default)."""

    def test_audit_event_no_op_when_disabled(self, tmp_dir):
        from flask import Flask
        app = Flask(__name__)
        db_path = os.path.join(tmp_dir, 'audit.db')
        store = AuditStore(db_path)
        app.config['ODPSC'] = {'audit_enabled': False}
        app.config['AUDIT_STORE'] = store

        audit_event(app, 'bundle_received', bundle_id='bid-test')
        events = store.get_events()
        assert len(events) == 0

    def test_audit_event_no_op_without_store(self):
        from flask import Flask
        app = Flask(__name__)
        app.config['ODPSC'] = {'audit_enabled': True}
        # No AUDIT_STORE configured
        audit_event(app, 'bundle_received', bundle_id='bid-test')
        # Should not crash


class TestAuditEndpoint:
    """Tests for GET /api/v2/audit endpoint."""

    def test_audit_endpoint_returns_events(self, audit_client, auth_headers):
        # Upload a bundle to generate audit event
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('manifest.json', json.dumps({
                'bundle_id': 'audit-test-001',
                'hostname': 'test-host',
                'level': 'L1',
            }))
        zip_buffer.seek(0)

        headers = {
            'Authorization': 'Bearer test-api-key-12345',
            'X-ODPSC-Bundle-ID': 'audit-test-001',
        }
        audit_client.post(
            '/api/v2/bundles/upload',
            data={'bundle': (zip_buffer, 'test.zip')},
            headers=headers,
            content_type='multipart/form-data',
        )

        resp = audit_client.get('/api/v2/audit', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'events' in data
        assert 'total' in data
        assert data['total'] >= 1

    def test_audit_endpoint_pagination(self, audit_client, auth_headers):
        resp = audit_client.get(
            '/api/v2/audit?limit=5&offset=0',
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'events' in data
        assert 'count' in data

    def test_audit_endpoint_filter_by_type(self, audit_client, auth_headers):
        resp = audit_client.get(
            '/api/v2/audit?event_type=bundle_received',
            headers=auth_headers,
        )
        assert resp.status_code == 200

    def test_audit_endpoint_requires_auth(self, audit_client):
        resp = audit_client.get('/api/v2/audit')
        assert resp.status_code == 401

    def test_audit_endpoint_disabled(self, client, auth_headers):
        # client uses default config with audit_enabled=False
        resp = client.get('/api/v2/audit', headers=auth_headers)
        assert resp.status_code == 403


class TestAuditBundleEndpoint:
    """Tests for GET /api/v2/audit/<bundle_id> endpoint."""

    def test_audit_bundle_returns_events(self, audit_client, auth_headers):
        # Upload a bundle
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('manifest.json', json.dumps({
                'bundle_id': 'audit-bundle-001',
                'hostname': 'test-host',
                'level': 'L1',
            }))
        zip_buffer.seek(0)

        headers = {
            'Authorization': 'Bearer test-api-key-12345',
            'X-ODPSC-Bundle-ID': 'audit-bundle-001',
        }
        audit_client.post(
            '/api/v2/bundles/upload',
            data={'bundle': (zip_buffer, 'test.zip')},
            headers=headers,
            content_type='multipart/form-data',
        )

        resp = audit_client.get(
            '/api/v2/audit/audit-bundle-001',
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['bundle_id'] == 'audit-bundle-001'
        assert 'events' in data
        assert data['count'] >= 1

    def test_audit_bundle_no_events(self, audit_client, auth_headers):
        resp = audit_client.get(
            '/api/v2/audit/nonexistent-bundle',
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['count'] == 0

    def test_audit_bundle_requires_auth(self, audit_client):
        resp = audit_client.get('/api/v2/audit/some-bundle')
        assert resp.status_code == 401

    def test_audit_bundle_disabled(self, client, auth_headers):
        resp = client.get('/api/v2/audit/some-bundle', headers=auth_headers)
        assert resp.status_code == 403


class TestContentSummary:
    """Tests for generate_content_summary."""

    def test_generates_summary_for_valid_zip(self, tmp_dir):
        zip_path = os.path.join(tmp_dir, 'test.zip')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('manifest.json', '{"bundle_id": "test"}')
            zf.writestr('system_info.json', '{"hostname": "node1"}')
            zf.writestr('configs/core-site.xml', '<configuration/>')

        summary = generate_content_summary(zip_path)
        entries = json.loads(summary)
        assert len(entries) == 3
        filenames = [e['filename'] for e in entries]
        assert 'manifest.json' in filenames
        assert 'system_info.json' in filenames
        assert all('size' in e for e in entries)

    def test_generates_empty_for_invalid_zip(self, tmp_dir):
        bad_path = os.path.join(tmp_dir, 'bad.zip')
        with open(bad_path, 'w') as f:
            f.write('not a zip')
        summary = generate_content_summary(bad_path)
        assert summary == '[]'

    def test_generates_empty_for_missing_file(self):
        summary = generate_content_summary('/nonexistent/file.zip')
        assert summary == '[]'
