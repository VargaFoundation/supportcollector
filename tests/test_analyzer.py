"""
Tests for the ODPSC Log Analyzer module.
"""

from analyzer import analyze_logs, generate_text_report


class TestAnalyzeLogs:
    """Tests for the analyze_logs function."""

    def test_empty_logs(self):
        result = analyze_logs({})
        assert result['total_files_analyzed'] == 0
        assert result['total_lines_analyzed'] == 0
        assert result['error_summary'] == {}
        assert result['anomalies'] == []

    def test_detects_error_patterns(self, sample_logs):
        result = analyze_logs(sample_logs)
        assert result['total_files_analyzed'] == 2
        assert result['error_summary'].get('ERROR', 0) >= 4
        assert result['error_summary'].get('FATAL', 0) >= 1
        assert result['error_summary'].get('OutOfMemoryError', 0) >= 1
        assert result['error_summary'].get('Exception', 0) >= 2

    def test_detects_oom_anomaly(self, sample_logs):
        result = analyze_logs(sample_logs)
        anomaly_types = [a['type'] for a in result['anomalies']]
        assert 'OutOfMemoryError' in anomaly_types

    def test_detects_fatal_anomaly(self, sample_logs):
        result = analyze_logs(sample_logs)
        anomaly_types = [a['type'] for a in result['anomalies']]
        assert 'FATAL_ERRORS' in anomaly_types

    def test_detects_unhealthy_nodes(self, sample_logs):
        result = analyze_logs(sample_logs)
        assert result['error_summary'].get('NodeUnhealthy', 0) >= 1
        anomaly_types = [a['type'] for a in result['anomalies']]
        assert 'UNHEALTHY_NODES' in anomaly_types

    def test_per_file_summary(self, sample_logs):
        result = analyze_logs(sample_logs)
        assert len(result['per_file_summary']) == 2
        for filepath, summary in result['per_file_summary'].items():
            assert 'total_lines' in summary
            assert 'pattern_counts' in summary

    def test_extracts_exceptions(self, sample_logs):
        result = analyze_logs(sample_logs)
        assert len(result['top_exceptions']) > 0

    def test_single_file_no_errors(self):
        logs = {'/var/log/test.log': "INFO Starting service\nINFO Service ready\n"}
        result = analyze_logs(logs)
        assert result['total_files_analyzed'] == 1
        assert result['error_summary'] == {}
        assert result['anomalies'] == []

    def test_high_error_rate_anomaly(self):
        # More than 10% error lines
        lines = ["ERROR something broke\n"] * 20 + ["INFO ok\n"] * 80
        logs = {'/var/log/test.log': ''.join(lines)}
        result = analyze_logs(logs)
        anomaly_types = [a['type'] for a in result['anomalies']]
        assert 'HIGH_ERROR_RATE' in anomaly_types

    def test_recurring_errors_detected(self):
        # Create logs with many ERROR entries to trigger recurring detection
        lines = []
        for i in range(50):
            lines.append(f"2025-01-15 10:{i:02d}:00 ERROR something failed\n")
        for i in range(200):
            lines.append(f"2025-01-15 11:00:{i:02d} INFO normal operation\n")
        logs = {'/var/log/test.log': ''.join(lines)}
        result = analyze_logs(logs)
        assert len(result['recurring_errors']) > 0


class TestGenerateTextReport:
    """Tests for the text report generation."""

    def test_generates_report(self, sample_logs):
        analysis = analyze_logs(sample_logs)
        report = generate_text_report(analysis)
        assert 'ODPSC DIAGNOSTIC ANALYSIS REPORT' in report
        assert 'END OF REPORT' in report

    def test_report_includes_anomalies(self, sample_logs):
        analysis = analyze_logs(sample_logs)
        report = generate_text_report(analysis)
        assert 'ANOMALIES DETECTED' in report

    def test_report_includes_error_summary(self, sample_logs):
        analysis = analyze_logs(sample_logs)
        report = generate_text_report(analysis)
        assert 'ERROR SUMMARY' in report

    def test_empty_report(self):
        analysis = analyze_logs({})
        report = generate_text_report(analysis)
        assert 'ODPSC DIAGNOSTIC ANALYSIS REPORT' in report
        assert 'Files analyzed: 0' in report
