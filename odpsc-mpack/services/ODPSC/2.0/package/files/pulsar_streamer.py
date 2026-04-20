"""
ODPSC Pulsar Streamer — continuous streaming of metrics and logs to the
SupportPlane backend via Apache Pulsar.

This is an opt-in complement to the existing bundle-upload path:
 - Bundle upload remains the source of truth for configs, diagnostics,
   thread dumps, and any heavy artifacts.
 - The streamer publishes fine-grained metrics and log tails continuously
   so the SupportPlane AI engine gets sub-minute visibility instead of
   waiting for the next bundle (L1 = 1h, L2 = 24h, L3 = on-demand).

Topics (namespace-per-tenant isolation when upgraded):
    persistent://supportplane/{tenant_ns}/metrics
    persistent://supportplane/{tenant_ns}/logs

Install with:
    pip install 'pulsar-client>=3.4.0'

This module degrades gracefully if pulsar-client is not installed —
streaming is disabled and only bundle uploads happen, so ops teams that
don't want to run Pulsar can ignore it entirely.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger('odpsc-streamer')

try:
    import pulsar  # type: ignore
    _PULSAR_AVAILABLE = True
except ImportError:
    pulsar = None
    _PULSAR_AVAILABLE = False


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PulsarStreamer:
    """
    Continuous streaming producer.

    One instance per agent process. Reuses a single Pulsar client and two
    long-lived producers (metrics + logs). Batching + LZ4 compression keep
    throughput high without pressuring the Pulsar broker.
    """

    def __init__(
        self,
        service_url: str,
        tenant: str = 'supportplane',
        tenant_namespace: str = 'default',
        cluster_id: Optional[int] = None,
        external_cluster_id: str = 'unknown',
        node_id: Optional[str] = None,
        batching_max_messages: int = 500,
        batching_max_publish_delay_ms: int = 50,
        connect_timeout_ms: int = 10_000,
        auth_token: Optional[str] = None,
        tls_trust_certs_file_path: Optional[str] = None,
        tls_allow_insecure_connection: bool = False,
    ) -> None:
        self.service_url = service_url
        self.tenant = tenant
        self.tenant_namespace = tenant_namespace
        self.cluster_id = cluster_id
        self.external_cluster_id = external_cluster_id
        self.node_id = node_id or socket.gethostname()
        self._client = None
        self._metrics_producer = None
        self._logs_producer = None
        self._lock = threading.Lock()

        self._batching_max_messages = batching_max_messages
        self._batching_max_publish_delay_ms = batching_max_publish_delay_ms
        self._connect_timeout_ms = connect_timeout_ms
        self._auth_token = auth_token or None
        self._tls_trust_certs_file_path = tls_trust_certs_file_path or None
        self._tls_allow_insecure_connection = tls_allow_insecure_connection

    # --------------------------------------------------------------- lifecycle

    def connect(self) -> bool:
        if not _PULSAR_AVAILABLE:
            logger.warning("pulsar-client not installed — streaming disabled")
            return False
        if self._client is not None:
            return True
        try:
            client_kwargs = {
                'operation_timeout_seconds': self._connect_timeout_ms // 1000,
                'connection_timeout_ms': self._connect_timeout_ms,
            }
            if self._auth_token:
                client_kwargs['authentication'] = pulsar.AuthenticationToken(self._auth_token)
            if self._tls_trust_certs_file_path:
                client_kwargs['tls_trust_certs_file_path'] = self._tls_trust_certs_file_path
                client_kwargs['tls_allow_insecure_connection'] = self._tls_allow_insecure_connection
                client_kwargs['tls_validate_hostname'] = not self._tls_allow_insecure_connection
            self._client = pulsar.Client(self.service_url, **client_kwargs)
            self._metrics_producer = self._create_producer('metrics')
            self._logs_producer = self._create_producer('logs')
            logger.info(
                "Pulsar streamer connected to %s (ns=%s, tls=%s, auth=%s)",
                self.service_url, self.tenant_namespace,
                bool(self._tls_trust_certs_file_path),
                bool(self._auth_token),
            )
            return True
        except Exception as e:
            logger.warning("Pulsar connection failed (%s): %s", self.service_url, e)
            self.close()
            return False

    def _create_producer(self, topic: str):
        full_topic = f"persistent://{self.tenant}/{self.tenant_namespace}/{topic}"
        return self._client.create_producer(
            full_topic,
            block_if_queue_full=False,
            batching_enabled=True,
            batching_max_messages=self._batching_max_messages,
            batching_max_publish_delay_ms=self._batching_max_publish_delay_ms,
            compression_type=pulsar.CompressionType.LZ4,
            send_timeout_millis=30_000,
        )

    def close(self) -> None:
        with self._lock:
            for p in (self._metrics_producer, self._logs_producer):
                if p is not None:
                    try:
                        p.flush()
                        p.close()
                    except Exception:
                        pass
            if self._client is not None:
                try:
                    self._client.close()
                except Exception:
                    pass
            self._client = None
            self._metrics_producer = None
            self._logs_producer = None

    @property
    def enabled(self) -> bool:
        return self._metrics_producer is not None and self._logs_producer is not None

    # ----------------------------------------------------------- publish API

    def publish_host_metrics(self, metrics: Dict[str, float], timestamp: Optional[str] = None) -> None:
        envelope = {
            'tenantId': self.tenant_namespace,
            'clusterId': self.cluster_id,
            'nodeId': self.node_id,
            'kind': 'host',
            'timestamp': timestamp or _utc_now_iso(),
            'metrics': self._only_numeric(metrics),
        }
        self._send_metric(envelope)

    def publish_jmx_metrics(
        self,
        service: str,
        component: str,
        metrics: Dict[str, float],
        timestamp: Optional[str] = None,
    ) -> None:
        envelope = {
            'tenantId': self.tenant_namespace,
            'clusterId': self.cluster_id,
            'nodeId': self.node_id,
            'kind': 'jmx',
            'service': service,
            'component': component,
            'timestamp': timestamp or _utc_now_iso(),
            'metrics': self._only_numeric(metrics),
        }
        self._send_metric(envelope)

    def publish_log_tail(
        self,
        service: str,
        level: str,
        lines: List[str],
    ) -> None:
        if not lines:
            return
        envelope = {
            'tenantId': self.tenant_namespace,
            'clusterId': self.external_cluster_id,
            'nodeId': self.node_id,
            'service': service,
            'level': level,
            'timestamp': _utc_now_iso(),
            'lines': lines,
        }
        self._send_log(envelope)

    # ----------------------------------------------------------- internals

    def _send_metric(self, envelope: Dict[str, Any]) -> None:
        if not self._metrics_producer or not envelope.get('metrics'):
            return
        payload = json.dumps(envelope, default=str).encode('utf-8')
        key = f"{envelope.get('clusterId', '?')}::{envelope.get('nodeId', '?')}"
        try:
            self._metrics_producer.send_async(
                payload,
                callback=self._on_send,
                partition_key=key,
            )
        except Exception as e:
            logger.debug("Metric publish failed: %s", e)

    def _send_log(self, envelope: Dict[str, Any]) -> None:
        if not self._logs_producer:
            return
        payload = json.dumps(envelope, default=str).encode('utf-8')
        key = f"{envelope.get('clusterId', '?')}::{envelope.get('nodeId', '?')}"
        try:
            self._logs_producer.send_async(
                payload,
                callback=self._on_send,
                partition_key=key,
            )
        except Exception as e:
            logger.debug("Log publish failed: %s", e)

    @staticmethod
    def _on_send(res, msg_id) -> None:
        if pulsar and res != pulsar.Result.Ok:
            logger.debug("Pulsar send result=%s", res)

    @staticmethod
    def _only_numeric(values: Dict[str, Any]) -> Dict[str, float]:
        out: Dict[str, float] = {}
        for k, v in (values or {}).items():
            if isinstance(v, bool):
                continue
            if isinstance(v, (int, float)):
                out[k] = float(v)
        return out


# --------------------------------------------------------- scheduling helper

def run_streaming_loop(
    streamer: PulsarStreamer,
    collect_fn: Callable[[], Dict[str, float]],
    interval_seconds: int = 15,
    stop_event: Optional[threading.Event] = None,
) -> None:
    """
    Minimal streaming loop suitable for a daemon thread.

    Calls ``collect_fn`` every ``interval_seconds`` and publishes the
    result as host metrics. Callers that want jmx/log publishing should
    wire their own scheduler — this helper is only for the simplest case.
    """
    if not streamer.connect():
        return
    stop_event = stop_event or threading.Event()
    while not stop_event.is_set():
        try:
            metrics = collect_fn() or {}
            if metrics:
                streamer.publish_host_metrics(metrics)
        except Exception as e:
            logger.warning("Streaming iteration failed: %s", e)
        stop_event.wait(interval_seconds)


def build_from_config(cfg: Dict[str, Any]) -> Optional[PulsarStreamer]:
    """Build a streamer from the agent config dict, or return None when disabled."""
    streaming = (cfg or {}).get('streaming', {})
    if not streaming.get('enabled', False):
        return None
    service_url = streaming.get('pulsar_service_url') or os.environ.get('PULSAR_SERVICE_URL')
    if not service_url:
        logger.warning("streaming.enabled=true but no pulsar_service_url configured")
        return None

    # Auth + TLS material — see ADR 0003 (supportplane repo) for the full
    # security model. The token is a JWT issued by SupportPlane to this
    # tenant; the CA cert validates the Pulsar Proxy's TLS cert.
    auth_token = (
        _read_optional_file(streaming.get('pulsar_auth_token_file'))
        or streaming.get('pulsar_auth_token')
        or os.environ.get('PULSAR_AUTH_TOKEN')
    )
    tls_trust_certs = (
        streaming.get('pulsar_tls_trust_certs_file_path')
        or os.environ.get('PULSAR_TLS_TRUST_CERTS')
    )
    tls_allow_insecure = bool(streaming.get('pulsar_tls_allow_insecure_connection', False))

    if service_url.startswith('pulsar+ssl://') and not tls_trust_certs and not tls_allow_insecure:
        logger.warning(
            "streaming.pulsar_service_url uses TLS but no CA cert configured "
            "(set streaming.pulsar_tls_trust_certs_file_path)"
        )

    return PulsarStreamer(
        service_url=service_url,
        tenant=streaming.get('pulsar_tenant', 'supportplane'),
        tenant_namespace=streaming.get('tenant_namespace', 'default'),
        cluster_id=cfg.get('cluster_db_id'),
        external_cluster_id=cfg.get('cluster_id', 'unknown'),
        node_id=cfg.get('node_id'),
        auth_token=auth_token,
        tls_trust_certs_file_path=tls_trust_certs,
        tls_allow_insecure_connection=tls_allow_insecure,
    )


def _read_optional_file(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return fh.read().strip()
    except OSError as e:
        logger.warning("Failed to read pulsar auth token file %s: %s", path, e)
        return None
