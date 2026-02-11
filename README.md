# ODP Support Collector (ODPSC)

Automated diagnostic collection solution for Hadoop clusters running the ODP (Open Data Platform) distribution. ODPSC collects logs, metrics, configurations, and system information from all cluster nodes, analyzes them for anomalies, and sends diagnostic bundles to ODP support teams.

Inspired by Hortonworks SmartSense and Cloudera Diagnostic Data Collection.

## Features

- **Automatic collection** - Scheduled weekly (configurable: daily, weekly, monthly) via cron
- **Log analysis** - Detects ERROR/FATAL/Exception patterns, OutOfMemoryError, unhealthy nodes, SafeMode
- **Sensitive data masking** - Passwords, tokens, and secrets are automatically masked in collected configs
- **AES-256 encryption** - Bundles are optionally encrypted before storage or transmission
- **Ambari integration** - Deploys as an Ambari service via Management Pack with UI-configurable properties
- **Manual mode** - Trigger collection on-demand via REST API; store bundles in HDFS without sending
- **REST API** - Full API for collection triggers, configuration management, and status checks

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Ambari Server                      │
│  ┌─────────────────────────────────────────────────┐ │
│  │              ODPSC Master (port 8085)           │ │
│  │  - Receives agent bundles                       │ │
│  │  - Aggregates & analyzes logs                   │ │
│  │  - Sends to support / stores in HDFS            │ │
│  │  - Scheduled collection via cron                │ │
│  └─────────────────────────────────────────────────┘ │
└──────────────────┬───────────────────────────────────┘
                   │ HTTP (port 8085)
       ┌───────────┼───────────┐
       │           │           │
  ┌────▼───┐  ┌───▼────┐  ┌───▼────┐
  │ Agent  │  │ Agent  │  │ Agent  │
  │ Node 1 │  │ Node 2 │  │ Node N │
  └────────┘  └────────┘  └────────┘
  Collects:   Collects:   Collects:
  - Logs      - Logs      - Logs
  - Metrics   - Metrics   - Metrics
  - Configs   - Configs   - Configs
  - Sys Info  - Sys Info  - Sys Info
```

## Prerequisites

- Apache Ambari 2.7+
- Python 3.6+
- Hadoop cluster with HDFS (for manual mode bundle storage)

## Quick Start

### 1. Build the Management Pack

```bash
./build_mpack.sh
```

This produces `build/odpsc-mpack-1.0.tar.gz`.

### 2. Install in Ambari

```bash
ambari-server install-mpack --mpack=build/odpsc-mpack-1.0.tar.gz
ambari-server restart
```

### 3. Add the Service

1. Open Ambari UI
2. Go to **Actions > Add Service**
3. Select **ODP Support Collector**
4. Assign **ODPSC Master** to the Ambari Server host
5. **ODPSC Agent** is automatically deployed to all cluster nodes
6. Configure properties (support endpoint, token, collection frequency, etc.)
7. Deploy

### 4. Verify

```bash
# Check master status
curl -u admin:admin http://ambari-server:8085/api/v1/status

# Trigger manual collection (stored in HDFS)
curl -u admin:admin -X POST http://ambari-server:8085/api/v1/collect \
  -H 'Content-Type: application/json' \
  -d '{"send": false}'

# Trigger collection and send to support
curl -u admin:admin -X POST http://ambari-server:8085/api/v1/collect \
  -H 'Content-Type: application/json' \
  -d '{"send": true}'
```

## Project Structure

```
supportcollector/
├── odpsc-mpack/                          # Ambari Management Pack
│   ├── metainfo.xml                      # Mpack metadata
│   └── services/ODPSC/
│       ├── metainfo.xml                  # Service & component definitions
│       ├── configuration/
│       │   └── odpsc-site.xml            # Ambari-managed configuration properties
│       ├── scripts/
│       │   ├── master.py                 # Ambari lifecycle script (ODPSC Master)
│       │   └── agent.py                  # Ambari lifecycle script (ODPSC Agent)
│       └── resources/
│           ├── odpsc_master.py           # Master Flask server
│           ├── odpsc_agent.py            # Agent collection daemon
│           ├── analyzer.py               # Log analysis engine
│           └── requirements.txt          # Python dependencies
├── configs/                              # Default config templates
│   ├── master_config.json
│   └── agent_config.json
├── tests/                                # Unit tests
│   ├── conftest.py
│   ├── test_agent.py
│   ├── test_master.py
│   └── test_analyzer.py
├── openapi.yaml                          # OpenAPI 3.0 specification
├── build_mpack.sh                        # Build script
├── requirements.txt                      # Runtime dependencies
├── requirements-dev.txt                  # Development dependencies
├── setup.py                              # Package setup
├── SPEC.md                               # Functional specification
└── README.md
```

## Configuration

All properties are configurable via the Ambari UI under the ODPSC service configuration tab (`odpsc-site`).

| Property | Default | Description |
|---|---|---|
| `collection_enabled` | `true` | Enable/disable all diagnostic collection |
| `auto_send_enabled` | `true` | Enable/disable automatic sending to support |
| `send_frequency` | `weekly` | Collection frequency: `daily`, `weekly`, `monthly` |
| `support_endpoint` | `https://support.odp.com/upload` | Support upload URL |
| `support_token` | *(empty)* | Bearer token for support API authentication |
| `hdfs_path` | `/odpsc/diagnostics` | HDFS path for manual mode bundle storage |
| `log_paths` | `["/var/log/hadoop/*", ...]` | JSON list of log file glob patterns |
| `master_port` | `8085` | Master REST API port |
| `admin_username` | `admin` | Basic Auth username for API |
| `admin_password` | `admin` | Basic Auth password for API |
| `encryption_key` | *(empty)* | AES-256 encryption key (base64); auto-generated if empty |
| `log_retention_days` | `7` | Number of days of logs to collect |
| `max_log_size_mb` | `1` | Maximum log size per file (MB) |
| `ambari_server_url` | `http://localhost:8080` | Ambari Server URL |
| `cluster_name` | `cluster` | Ambari cluster name |

## REST API

The ODPSC Master exposes a REST API on port 8085 (configurable). See `openapi.yaml` for the full OpenAPI 3.0 specification.

### Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/submit_data` | None | Agent bundle submission (internal) |
| `POST` | `/api/v1/collect` | Basic | Trigger manual collection |
| `GET` | `/api/v1/config` | Basic | Get current configuration |
| `POST` | `/api/v1/config` | Basic | Update configuration |
| `GET` | `/api/v1/status` | Basic | Get master status |

### Examples

```bash
# Get current configuration
curl -u admin:admin http://ambari-server:8085/api/v1/config

# Disable auto-send
curl -u admin:admin -X POST http://ambari-server:8085/api/v1/config \
  -H 'Content-Type: application/json' \
  -d '{"auto_send_enabled": false}'

# Check status
curl -u admin:admin http://ambari-server:8085/api/v1/status
```

## Development

### Setup

```bash
pip install -r requirements-dev.txt
```

### Run Tests

```bash
pytest tests/ -v
```

### Run with Coverage

```bash
pytest tests/ --cov=odpsc-mpack/services/ODPSC/resources -v
```

### Build Mpack

```bash
./build_mpack.sh
```

## Collected Data

Each diagnostic bundle contains:

| Category | Contents |
|---|---|
| **Logs** | Last N days of Hadoop service logs (HDFS, YARN, Hive, Spark) |
| **Metrics** | CPU, memory, swap, disk I/O, network I/O, load averages, Ambari metrics |
| **Configs** | Service configuration files with sensitive values masked |
| **System Info** | Hostname, IP, OS version, Java version, uptime |
| **Analysis** | Error pattern counts, exception stack traces, anomaly detection report |

## Security

- **Sensitive data masking**: Passwords, tokens, and secrets are masked (`****MASKED****`) in all collected configuration files
- **Bundle encryption**: Optional AES-256 encryption for bundles at rest
- **HTTPS**: Bundles are sent to the support endpoint over HTTPS with Bearer token authentication
- **Basic Auth**: All management API endpoints require Basic Auth credentials
- **No credential storage**: Support tokens and passwords are stored in Ambari's secure configuration

## License

Apache License 2.0
