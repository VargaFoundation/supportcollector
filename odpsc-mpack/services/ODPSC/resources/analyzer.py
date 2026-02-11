"""
ODPSC Log Analyzer - Parses collected logs to detect anomalies and recurring errors.
"""

import re
from collections import Counter, defaultdict
from datetime import datetime


# Patterns indicating errors or anomalies in Hadoop logs
ERROR_PATTERNS = [
    (r'\bERROR\b', 'ERROR'),
    (r'Exception', 'Exception'),
    (r'\bFATAL\b', 'FATAL'),
    (r'\bOutOfMemoryError\b', 'OutOfMemoryError'),
    (r'\bConnectionRefused\b', 'ConnectionRefused'),
    (r'\bTimeout\b', 'Timeout'),
    (r'\bDiskSpaceExceeded\b', 'DiskSpaceExceeded'),
    (r'\bPermissionDenied\b', 'PermissionDenied'),
    (r'\bNodeUnhealthy\b', 'NodeUnhealthy'),
    (r'\bSafeMode\b', 'SafeMode'),
]

# Compiled regex for performance
COMPILED_PATTERNS = [(re.compile(p), name) for p, name in ERROR_PATTERNS]

# Pattern to extract Java exception stack traces
STACK_TRACE_PATTERN = re.compile(
    r'((?:\w+\.)+\w+(?:Error|Exception)(?::\s*.*)?'
    r'(?:\n\s+at\s+.*)*)',
    re.MULTILINE
)

# Pattern to extract log timestamps (common Hadoop log format)
TIMESTAMP_PATTERN = re.compile(
    r'(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})'
)


def analyze_logs(logs_data):
    """
    Analyze collected logs and produce a summary report.

    Args:
        logs_data: dict mapping file paths to their log content strings.

    Returns:
        dict with analysis results including error counts, top errors,
        stack traces, and per-file summaries.
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
    }

    global_error_counts = Counter()
    exception_messages = Counter()
    error_timeline = defaultdict(list)

    for filepath, content in logs_data.items():
        file_report = _analyze_single_file(filepath, content)
        report['per_file_summary'][filepath] = file_report
        report['total_lines_analyzed'] += file_report['total_lines']

        # Aggregate counts
        for pattern_name, count in file_report['pattern_counts'].items():
            global_error_counts[pattern_name] += count

        for exc, count in file_report['exception_counts'].items():
            exception_messages[exc] += count

        for ts, pattern_name in file_report['error_timestamps']:
            error_timeline[pattern_name].append(ts)

    report['error_summary'] = dict(global_error_counts)
    report['top_exceptions'] = [
        {'exception': exc, 'count': count}
        for exc, count in exception_messages.most_common(20)
    ]

    # Detect recurring errors (same error appearing frequently)
    report['recurring_errors'] = _detect_recurring_errors(error_timeline)

    # Detect anomalies
    report['anomalies'] = _detect_anomalies(report)

    return report


def _analyze_single_file(filepath, content):
    """Analyze a single log file."""
    lines = content.split('\n')
    result = {
        'total_lines': len(lines),
        'pattern_counts': Counter(),
        'exception_counts': Counter(),
        'error_timestamps': [],
        'sample_errors': [],
    }

    for line in lines:
        for compiled_re, pattern_name in COMPILED_PATTERNS:
            if compiled_re.search(line):
                result['pattern_counts'][pattern_name] += 1

                # Extract timestamp if available
                ts_match = TIMESTAMP_PATTERN.search(line)
                if ts_match:
                    result['error_timestamps'].append(
                        (ts_match.group(1), pattern_name)
                    )

                # Keep sample errors (up to 5 per pattern)
                samples_for_pattern = [
                    s for s in result['sample_errors']
                    if s['pattern'] == pattern_name
                ]
                if len(samples_for_pattern) < 5:
                    result['sample_errors'].append({
                        'pattern': pattern_name,
                        'line': line[:500],  # Truncate long lines
                    })

    # Extract exception stack traces
    for match in STACK_TRACE_PATTERN.finditer(content):
        exc_text = match.group(0)
        # Use the first line as the key
        exc_key = exc_text.split('\n')[0][:200]
        result['exception_counts'][exc_key] += 1

    # Convert Counter to dict for JSON serialization
    result['pattern_counts'] = dict(result['pattern_counts'])
    result['exception_counts'] = dict(result['exception_counts'])

    return result


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


def _detect_anomalies(report):
    """Detect anomalies based on the analysis report."""
    anomalies = []

    error_summary = report.get('error_summary', {})

    if error_summary.get('OutOfMemoryError', 0) > 0:
        anomalies.append({
            'type': 'OutOfMemoryError',
            'severity': 'CRITICAL',
            'message': (
                f"OutOfMemoryError detected "
                f"{error_summary['OutOfMemoryError']} time(s). "
                f"Check JVM heap settings."
            ),
        })

    if error_summary.get('FATAL', 0) > 0:
        anomalies.append({
            'type': 'FATAL_ERRORS',
            'severity': 'CRITICAL',
            'message': (
                f"FATAL errors detected "
                f"{error_summary['FATAL']} time(s)."
            ),
        })

    if error_summary.get('SafeMode', 0) > 0:
        anomalies.append({
            'type': 'HDFS_SAFE_MODE',
            'severity': 'HIGH',
            'message': 'HDFS SafeMode entries detected. HDFS may be in read-only state.',
        })

    if error_summary.get('NodeUnhealthy', 0) > 0:
        anomalies.append({
            'type': 'UNHEALTHY_NODES',
            'severity': 'HIGH',
            'message': (
                f"NodeUnhealthy markers detected "
                f"{error_summary['NodeUnhealthy']} time(s). "
                f"Check YARN NodeManager health."
            ),
        })

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

    return anomalies


def generate_text_report(analysis):
    """Generate a human-readable text report from analysis results."""
    lines = []
    lines.append("=" * 70)
    lines.append("ODPSC DIAGNOSTIC ANALYSIS REPORT")
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

    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)

    return '\n'.join(lines)
