"""
ODPSC Log Analyzer v2 - Parses collected logs to detect anomalies and recurring errors.
Features categorized Hadoop patterns, severity levels, service-aware routing,
temporal analysis with spike detection, and actionable recommendations.
"""

import re
from collections import Counter, defaultdict
from datetime import datetime


# Categorized Hadoop patterns with severity levels
HADOOP_PATTERNS = {
    'hdfs': [
        (r'BlockMissingException', 'BlockMissingException', 'CRITICAL'),
        (r'corrupt\s+block', 'CorruptBlock', 'CRITICAL'),
        (r'under[_-]?replicat', 'UnderReplication', 'HIGH'),
        (r'Lease\s+\S+\s+on\s+file\s+\S+\s+has\s+expired', 'LeaseExpiry', 'HIGH'),
        (r'\bSafeMode\b', 'SafeMode', 'HIGH'),
        (r'NameNode\s+is\s+in\s+safe\s+mode', 'SafeMode', 'HIGH'),
        (r'Could not obtain block', 'BlockAccessFailure', 'HIGH'),
    ],
    'yarn': [
        (r'\bNodeUnhealthy\b', 'NodeUnhealthy', 'HIGH'),
        (r'Container\s+\[?\w+\]?\s+is\s+running\s+beyond\s+(?:physical|virtual)\s+memory\s+limits',
         'ContainerOOM', 'CRITICAL'),
        (r'Container\s+killed\s+by\s+the\s+ApplicationMaster', 'ContainerKilled', 'MEDIUM'),
        (r'preempt(?:ing|ed)\s+container', 'Preemption', 'MEDIUM'),
        (r'Application\s+\S+\s+failed\s+\d+\s+times', 'AMFailure', 'HIGH'),
        (r'appattempt_\S+\s+failed', 'AMFailure', 'HIGH'),
    ],
    'jvm': [
        (r'\bOutOfMemoryError\b', 'OutOfMemoryError', 'CRITICAL'),
        (r'GC\s+pause.*?(\d+(?:\.\d+)?)\s*(?:ms|secs)', 'GCPause', 'HIGH'),
        (r'GC\s+overhead\s+limit\s+exceeded', 'GCOverhead', 'CRITICAL'),
        (r'Java\s+heap\s+space', 'HeapExhausted', 'CRITICAL'),
    ],
    'security': [
        (r'(?:GSS|Kerberos)\s*(?:initiate|accept)\s*failed', 'KerberosFailure', 'HIGH'),
        (r'javax\.security\.auth\.login\.LoginException', 'LoginException', 'HIGH'),
        (r'Unable\s+to\s+obtain\s+password\s+from\s+user', 'AuthFailure', 'HIGH'),
        (r'Failed\s+to\s+authenticate\s+user', 'AuthFailure', 'HIGH'),
    ],
    'zookeeper': [
        (r'Session\s+\S+\s+(?:has\s+)?expired', 'ZKSessionExpired', 'HIGH'),
        (r'Connection\s+loss', 'ZKConnectionLoss', 'HIGH'),
        (r'KeeperErrorCode\s*=\s*ConnectionLoss', 'ZKConnectionLoss', 'HIGH'),
    ],
    'hbase': [
        (r'region\s+split\s+(?:failed|error)', 'RegionSplitFailure', 'CRITICAL'),
        (r'NotServingRegionException', 'NotServingRegion', 'HIGH'),
        (r'RegionTooBusyException', 'RegionTooBusy', 'MEDIUM'),
    ],
    'general': [
        (r'\bERROR\b', 'ERROR', 'MEDIUM'),
        (r'\bFATAL\b', 'FATAL', 'CRITICAL'),
        (r'Exception', 'Exception', 'MEDIUM'),
        (r'\bConnectionRefused\b', 'ConnectionRefused', 'HIGH'),
        (r'\bTimeout\b', 'Timeout', 'MEDIUM'),
        (r'No\s+space\s+left\s+on\s+device|DiskSpaceExceeded|DiskFull', 'DiskFull', 'CRITICAL'),
        (r'\bPermissionDenied\b|Permission\s+denied', 'PermissionDenied', 'HIGH'),
    ],
}

# Recommendations per pattern type
RECOMMENDATIONS = {
    'BlockMissingException': 'Run `hdfs fsck /` to identify missing blocks. Consider increasing replication factor.',
    'CorruptBlock': 'Run `hdfs fsck / -list-corruptfileblocks` and `hdfs debug recoverLease` on affected files.',
    'UnderReplication': 'Check DataNode health with `hdfs dfsadmin -report`. Ensure sufficient DataNodes are running.',
    'LeaseExpiry': 'Check for long-running jobs holding file leases. Consider running `hdfs debug recoverLease`.',
    'SafeMode': 'HDFS is in read-only mode. Check NameNode logs and run `hdfs dfsadmin -safemode leave` if safe.',
    'BlockAccessFailure': 'Verify DataNode connectivity and check for disk failures on DataNodes.',
    'NodeUnhealthy': 'Check YARN NodeManager health script output. Common causes: disk full, high memory usage.',
    'ContainerOOM': 'Increase container memory limits (mapreduce.map.memory.mb / mapreduce.reduce.memory.mb).',
    'ContainerKilled': 'Review application logs for errors. Container may have exceeded resource limits.',
    'Preemption': 'Review YARN queue capacity settings. Higher-priority queues may be preempting containers.',
    'AMFailure': 'Check ApplicationMaster logs. Increase AM retry count (yarn.resourcemanager.am.max-attempts).',
    'OutOfMemoryError': 'Increase JVM heap size (-Xmx). Check for memory leaks. Review GC settings.',
    'GCPause': 'Tune GC parameters. Consider using G1GC. Increase heap size if GC pauses are frequent.',
    'GCOverhead': 'JVM spending too much time in GC. Increase heap or optimize memory usage.',
    'HeapExhausted': 'Java heap space exhausted. Increase -Xmx setting for the affected service.',
    'KerberosFailure': 'Check Kerberos KDC connectivity. Verify keytab files are valid with `klist -kt`.',
    'LoginException': 'Authentication failed. Check keytab permissions and principal configuration.',
    'AuthFailure': 'Authentication failed. Verify user credentials and Kerberos/LDAP configuration.',
    'ZKSessionExpired': 'ZooKeeper session expired. Check ZK ensemble health and network connectivity.',
    'ZKConnectionLoss': 'ZooKeeper connection lost. Check ZK server status and network between client and ZK.',
    'RegionSplitFailure': 'HBase region split failed. Check RegionServer logs and HDFS health.',
    'NotServingRegion': 'Region not served by any RegionServer. Check HBase Master for region assignment issues.',
    'RegionTooBusy': 'HBase region overloaded. Consider pre-splitting tables or adjusting region split policy.',
    'ConnectionRefused': 'Target service may be down. Check service status and network connectivity.',
    'DiskFull': 'Disk space exhausted. Free space or add storage capacity immediately.',
    'PermissionDenied': 'Permission denied. Check file/directory permissions and user/group settings.',
    'Timeout': 'Operation timed out. Check network latency and service responsiveness.',
    'FATAL': 'Fatal error detected. Review full stack trace and service logs for root cause.',
    'ERROR': 'Errors detected. Review error messages for specific issues.',
    'Exception': 'Exceptions detected. Review stack traces for root cause.',
}

# Service detection from file paths
SERVICE_PATH_PATTERNS = {
    'hdfs': [r'/hadoop.*namenode', r'/hadoop.*datanode', r'/hadoop.*hdfs', r'hdfs-'],
    'yarn': [r'/yarn', r'resourcemanager', r'nodemanager', r'yarn-'],
    'hbase': [r'/hbase', r'hbase-'],
    'zookeeper': [r'/zookeeper', r'zookeeper'],
    'security': [r'/kerberos', r'krb5', r'/security'],
}

# Compile all patterns for performance
_compiled_patterns = {}
for category, patterns in HADOOP_PATTERNS.items():
    _compiled_patterns[category] = [
        (re.compile(p, re.IGNORECASE), name, severity)
        for p, name, severity in patterns
    ]

_compiled_service_patterns = {
    svc: [re.compile(p, re.IGNORECASE) for p in patterns]
    for svc, patterns in SERVICE_PATH_PATTERNS.items()
}

# Pattern to extract Java exception stack traces
STACK_TRACE_PATTERN = re.compile(
    r'((?:\w+\.)+\w+(?:Error|Exception)(?::\s*.*)?'
    r'(?:\n\s+at\s+.*)*)',
    re.MULTILINE,
)

# Pattern to extract log timestamps (common Hadoop log format)
TIMESTAMP_PATTERN = re.compile(
    r'(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})'
)

# Temporal analysis: 5-minute window bucket format
TEMPORAL_BUCKET_FORMAT = '%Y-%m-%d %H:%M'
SPIKE_THRESHOLD = 3.0  # 3x average = spike


def _detect_service(filepath):
    """Detect which service a log file belongs to based on its path."""
    filepath_lower = filepath.lower()
    for service, compiled_list in _compiled_service_patterns.items():
        for pattern in compiled_list:
            if pattern.search(filepath_lower):
                return service
    return None


def _get_relevant_patterns(service):
    """Get relevant patterns for a detected service, plus general and security patterns."""
    patterns = list(_compiled_patterns.get('general', []))
    patterns.extend(_compiled_patterns.get('jvm', []))
    # Security patterns apply to all services
    patterns.extend(_compiled_patterns.get('security', []))

    if service and service in _compiled_patterns and service not in ('general', 'jvm', 'security'):
        patterns.extend(_compiled_patterns[service])

    # Always include all categories if no service detected
    if service is None:
        for cat in _compiled_patterns:
            if cat not in ('general', 'jvm', 'security'):
                patterns.extend(_compiled_patterns[cat])

    return patterns


def analyze_logs(logs_data):
    """
    Analyze collected logs and produce a summary report.

    Args:
        logs_data: dict mapping file paths to their log content strings.

    Returns:
        dict with analysis results including error counts, top errors,
        stack traces, temporal analysis, and per-file summaries.
    """
    report = {
        'timestamp': datetime.now(tz=None).isoformat(),
        'total_files_analyzed': len(logs_data),
        'total_lines_analyzed': 0,
        'error_summary': {},
        'per_file_summary': {},
        'top_exceptions': [],
        'recurring_errors': [],
        'anomalies': [],
        'temporal_analysis': {},
        'recommendations': [],
    }

    global_error_counts = Counter()
    exception_messages = Counter()
    error_timeline = defaultdict(list)
    temporal_buckets = defaultdict(Counter)  # bucket_key -> pattern -> count
    severity_counts = {}  # pattern -> severity

    for filepath, content in logs_data.items():
        service = _detect_service(filepath)
        file_report = _analyze_single_file(filepath, content, service)
        report['per_file_summary'][filepath] = file_report
        report['total_lines_analyzed'] += file_report['total_lines']

        for pattern_name, count in file_report['pattern_counts'].items():
            global_error_counts[pattern_name] += count

        for exc, count in file_report['exception_counts'].items():
            exception_messages[exc] += count

        for ts, pattern_name in file_report['error_timestamps']:
            error_timeline[pattern_name].append(ts)

        # Track severity per pattern
        for pname, sev in file_report.get('pattern_severities', {}).items():
            severity_counts[pname] = sev

        # Temporal bucketing
        for ts_str, pattern_name in file_report['error_timestamps']:
            bucket = _timestamp_to_bucket(ts_str)
            if bucket:
                temporal_buckets[bucket][pattern_name] += 1

    report['error_summary'] = dict(global_error_counts)
    report['top_exceptions'] = [
        {'exception': exc, 'count': count}
        for exc, count in exception_messages.most_common(20)
    ]

    report['recurring_errors'] = _detect_recurring_errors(error_timeline)
    report['anomalies'] = _detect_anomalies(report, severity_counts)
    report['temporal_analysis'] = _analyze_temporal(temporal_buckets)
    report['recommendations'] = _generate_recommendations(global_error_counts, severity_counts)

    return report


def _analyze_single_file(filepath, content, service=None):
    """Analyze a single log file with service-aware pattern matching."""
    lines = content.split('\n')
    patterns = _get_relevant_patterns(service)

    result = {
        'total_lines': len(lines),
        'pattern_counts': Counter(),
        'exception_counts': Counter(),
        'error_timestamps': [],
        'sample_errors': [],
        'detected_service': service,
        'pattern_severities': {},
    }

    for line in lines:
        for compiled_re, pattern_name, severity in patterns:
            if compiled_re.search(line):
                result['pattern_counts'][pattern_name] += 1
                result['pattern_severities'][pattern_name] = severity

                ts_match = TIMESTAMP_PATTERN.search(line)
                if ts_match:
                    result['error_timestamps'].append(
                        (ts_match.group(1), pattern_name)
                    )

                samples_for_pattern = [
                    s for s in result['sample_errors']
                    if s['pattern'] == pattern_name
                ]
                if len(samples_for_pattern) < 5:
                    result['sample_errors'].append({
                        'pattern': pattern_name,
                        'severity': severity,
                        'line': line[:500],
                    })

    # Extract exception stack traces
    for match in STACK_TRACE_PATTERN.finditer(content):
        exc_text = match.group(0)
        exc_key = exc_text.split('\n')[0][:200]
        result['exception_counts'][exc_key] += 1

    result['pattern_counts'] = dict(result['pattern_counts'])
    result['exception_counts'] = dict(result['exception_counts'])

    return result


def analyze_log_stream(lines_iter, service=None):
    """
    Analyze a stream of log lines one by one (memory-efficient).

    Args:
        lines_iter: iterable of log lines.
        service: optional service name for pattern routing.

    Yields:
        dict with pattern match info for each matching line.
    """
    patterns = _get_relevant_patterns(service)

    for line in lines_iter:
        for compiled_re, pattern_name, severity in patterns:
            if compiled_re.search(line):
                ts_match = TIMESTAMP_PATTERN.search(line)
                yield {
                    'pattern': pattern_name,
                    'severity': severity,
                    'timestamp': ts_match.group(1) if ts_match else None,
                    'line': line[:500],
                }


def _timestamp_to_bucket(ts_str):
    """Convert a timestamp string to a 5-minute bucket key."""
    try:
        dt = datetime.strptime(ts_str[:19].replace('T', ' '), '%Y-%m-%d %H:%M:%S')
        minute = (dt.minute // 5) * 5
        return dt.replace(minute=minute, second=0).strftime(TEMPORAL_BUCKET_FORMAT)
    except (ValueError, IndexError):
        return None


def _analyze_temporal(temporal_buckets):
    """Detect temporal spikes in error patterns."""
    if not temporal_buckets:
        return {'spikes': [], 'buckets': {}}

    # Convert to serializable format
    buckets_dict = {}
    for bucket_key, counts in sorted(temporal_buckets.items()):
        buckets_dict[bucket_key] = dict(counts)

    # Detect spikes per pattern
    pattern_totals = defaultdict(list)
    for bucket_key, counts in temporal_buckets.items():
        for pattern, count in counts.items():
            pattern_totals[pattern].append((bucket_key, count))

    spikes = []
    for pattern, bucket_counts in pattern_totals.items():
        if len(bucket_counts) < 2:
            continue
        counts_only = [c for _, c in bucket_counts]
        avg = sum(counts_only) / len(counts_only)
        if avg == 0:
            continue
        for bucket_key, count in bucket_counts:
            if count > avg * SPIKE_THRESHOLD:
                spikes.append({
                    'pattern': pattern,
                    'bucket': bucket_key,
                    'count': count,
                    'average': round(avg, 2),
                    'ratio': round(count / avg, 2),
                })

    spikes.sort(key=lambda x: x['ratio'], reverse=True)

    return {
        'spikes': spikes,
        'buckets': buckets_dict,
    }


def _detect_recurring_errors(error_timeline):
    """Detect patterns that appear with high frequency."""
    recurring = []
    for pattern_name, timestamps in error_timeline.items():
        count = len(timestamps)
        if count >= 10:
            recurring.append({
                'pattern': pattern_name,
                'count': count,
                'severity': 'HIGH' if count >= 100 else 'MEDIUM',
                'first_seen': min(timestamps) if timestamps else None,
                'last_seen': max(timestamps) if timestamps else None,
            })

    recurring.sort(key=lambda x: x['count'], reverse=True)
    return recurring


def _detect_anomalies(report, severity_counts):
    """Detect anomalies based on the analysis report."""
    anomalies = []
    error_summary = report.get('error_summary', {})

    # Check for critical patterns
    critical_patterns = [
        ('OutOfMemoryError', 'OutOfMemoryError', 'CRITICAL',
         'OutOfMemoryError detected {count} time(s). Check JVM heap settings.'),
        ('HeapExhausted', 'HeapExhausted', 'CRITICAL',
         'Java heap space exhausted {count} time(s). Increase -Xmx.'),
        ('GCOverhead', 'GCOverhead', 'CRITICAL',
         'GC overhead limit exceeded {count} time(s). Increase heap or optimize memory.'),
        ('FATAL', 'FATAL_ERRORS', 'CRITICAL',
         'FATAL errors detected {count} time(s).'),
        ('DiskFull', 'DISK_FULL', 'CRITICAL',
         'Disk full conditions detected {count} time(s). Free space immediately.'),
        ('BlockMissingException', 'MISSING_BLOCKS', 'CRITICAL',
         'Missing HDFS blocks detected {count} time(s). Run hdfs fsck.'),
        ('CorruptBlock', 'CORRUPT_BLOCKS', 'CRITICAL',
         'Corrupt HDFS blocks detected {count} time(s).'),
    ]

    for pattern_key, anomaly_type, severity, message_template in critical_patterns:
        count = error_summary.get(pattern_key, 0)
        if count > 0:
            anomalies.append({
                'type': anomaly_type,
                'severity': severity,
                'message': message_template.format(count=count),
            })

    # High severity patterns
    high_patterns = [
        ('SafeMode', 'HDFS_SAFE_MODE', 'HIGH',
         'HDFS SafeMode entries detected. HDFS may be in read-only state.'),
        ('NodeUnhealthy', 'UNHEALTHY_NODES', 'HIGH',
         'NodeUnhealthy markers detected {count} time(s). Check YARN NodeManager health.'),
        ('ContainerOOM', 'CONTAINER_OOM', 'HIGH',
         'Container OOM kills detected {count} time(s). Increase container memory limits.'),
        ('KerberosFailure', 'KERBEROS_FAILURE', 'HIGH',
         'Kerberos authentication failures detected {count} time(s). Check KDC and keytabs.'),
        ('ZKSessionExpired', 'ZK_SESSION_EXPIRED', 'HIGH',
         'ZooKeeper session expirations detected {count} time(s). Check ZK ensemble health.'),
    ]

    for pattern_key, anomaly_type, severity, message_template in high_patterns:
        count = error_summary.get(pattern_key, 0)
        if count > 0:
            anomalies.append({
                'type': anomaly_type,
                'severity': severity,
                'message': message_template.format(count=count),
            })

    # High error rate detection
    total_errors = error_summary.get('ERROR', 0)
    total_lines = report.get('total_lines_analyzed', 1)
    if total_lines > 0 and total_errors / total_lines > 0.1:
        anomalies.append({
            'type': 'HIGH_ERROR_RATE',
            'severity': 'HIGH',
            'message': (
                f"High error rate: {total_errors}/{total_lines} lines "
                f"({total_errors / total_lines * 100:.1f}%) contain errors."
            ),
        })

    # Temporal spike anomalies
    temporal = report.get('temporal_analysis', {})
    for spike in temporal.get('spikes', [])[:5]:
        if spike['ratio'] >= 5.0:
            anomalies.append({
                'type': 'ERROR_SPIKE',
                'severity': 'HIGH',
                'message': (
                    f"Error spike for {spike['pattern']} at {spike['bucket']}: "
                    f"{spike['count']} occurrences ({spike['ratio']}x average)."
                ),
            })

    return anomalies


def _generate_recommendations(error_counts, severity_counts):
    """Generate actionable recommendations based on detected patterns."""
    recommendations = []
    seen = set()

    # Sort by severity (CRITICAL first) then by count
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}

    sorted_patterns = sorted(
        error_counts.items(),
        key=lambda x: (severity_order.get(severity_counts.get(x[0], 'MEDIUM'), 2), -x[1]),
    )

    for pattern_name, count in sorted_patterns:
        if pattern_name in RECOMMENDATIONS and pattern_name not in seen:
            severity = severity_counts.get(pattern_name, 'MEDIUM')
            recommendations.append({
                'pattern': pattern_name,
                'severity': severity,
                'count': count,
                'recommendation': RECOMMENDATIONS[pattern_name],
            })
            seen.add(pattern_name)

    return recommendations


def generate_text_report(analysis):
    """Generate a human-readable text report from analysis results."""
    lines = []
    lines.append("=" * 70)
    lines.append("ODPSC DIAGNOSTIC ANALYSIS REPORT v2")
    lines.append(f"Generated: {analysis['timestamp']}")
    lines.append("=" * 70)
    lines.append("")

    lines.append(f"Files analyzed: {analysis['total_files_analyzed']}")
    lines.append(f"Total lines analyzed: {analysis['total_lines_analyzed']}")
    lines.append("")

    # Anomalies
    if analysis['anomalies']:
        lines.append("--- ANOMALIES DETECTED ---")
        for anomaly in analysis['anomalies']:
            lines.append(f"  [{anomaly['severity']}] {anomaly['type']}: {anomaly['message']}")
        lines.append("")

    # Error summary
    if analysis['error_summary']:
        lines.append("--- ERROR SUMMARY ---")
        for pattern, count in sorted(
            analysis['error_summary'].items(), key=lambda x: x[1], reverse=True
        ):
            lines.append(f"  {pattern}: {count}")
        lines.append("")

    # Top exceptions
    if analysis['top_exceptions']:
        lines.append("--- TOP EXCEPTIONS ---")
        for entry in analysis['top_exceptions'][:10]:
            lines.append(f"  ({entry['count']}x) {entry['exception']}")
        lines.append("")

    # Recurring errors
    if analysis['recurring_errors']:
        lines.append("--- RECURRING ERRORS ---")
        for entry in analysis['recurring_errors']:
            lines.append(
                f"  [{entry['severity']}] {entry['pattern']}: "
                f"{entry['count']} occurrences "
                f"(first: {entry['first_seen']}, last: {entry['last_seen']})"
            )
        lines.append("")

    # Temporal spikes
    temporal = analysis.get('temporal_analysis', {})
    spikes = temporal.get('spikes', [])
    if spikes:
        lines.append("--- TIMELINE (Error Spikes) ---")
        for spike in spikes[:10]:
            lines.append(
                f"  {spike['bucket']}: {spike['pattern']} = {spike['count']} "
                f"({spike['ratio']}x avg)"
            )
        lines.append("")

    # Recommendations
    recommendations = analysis.get('recommendations', [])
    if recommendations:
        lines.append("--- RECOMMENDATIONS ---")
        for rec in recommendations[:15]:
            lines.append(
                f"  [{rec['severity']}] {rec['pattern']} ({rec['count']}x): "
                f"{rec['recommendation']}"
            )
        lines.append("")

    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)

    return '\n'.join(lines)
