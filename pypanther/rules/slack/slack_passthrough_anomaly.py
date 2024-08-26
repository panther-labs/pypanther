from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import slack_alert_context

slack_audit_logs_passthrough_anomaly_tests: list[RuleTest] = [
    RuleTest(
        name="Name",
        expected_result=True,
        log={
            "action": "anomaly",
            "actor": {
                "type": "user",
                "user": {
                    "email": "user@example.com",
                    "id": "W012J3FEWAU",
                    "name": "primary-owner",
                    "team": "T01234N56GB",
                },
            },
            "context": {
                "ip_address": "1.2.3.4",
                "location": {
                    "domain": "test-workspace-1",
                    "id": "T01234N56GB",
                    "name": "test-workspace-1",
                    "type": "workspace",
                },
                "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
            },
        },
    ),
    RuleTest(
        name="User Logout",
        expected_result=False,
        log={
            "action": "user_logout",
            "actor": {
                "type": "user",
                "user": {
                    "email": "user@example.com",
                    "id": "W012J3FEWAU",
                    "name": "primary-owner",
                    "team": "T01234N56GB",
                },
            },
            "context": {
                "ip_address": "1.2.3.4",
                "location": {
                    "domain": "test-workspace-1",
                    "id": "T01234N56GB",
                    "name": "test-workspace-1",
                    "type": "workspace",
                },
                "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
            },
            "date_create": "2022-07-28 15:22:32",
            "entity": {
                "type": "user",
                "user": {
                    "email": "user@example.com",
                    "id": "W012J3FEWAU",
                    "name": "primary-owner",
                    "team": "T01234N56GB",
                },
            },
            "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
        },
    ),
]


@panther_managed
class SlackAuditLogsPassthroughAnomaly(Rule):
    id = "Slack.AuditLogs.PassthroughAnomaly-prototype"
    display_name = "Slack Anomaly Detected"
    log_types = [LogType.SLACK_AUDIT_LOGS]
    tags = ["Slack", "Command and Control", "Application Layer Protocol"]
    reports = {"MITRE ATT&CK": ["TA0011:T1071"]}
    default_severity = Severity.CRITICAL
    default_description = "Passthrough for anomalies detected by Slack"
    default_reference = "https://slack.com/intl/en-in/blog/news/three-new-security-features-to-protect-your-digital-hq"
    summary_attributes = ["p_any_ip_addresses", "p_any_emails"]
    tests = slack_audit_logs_passthrough_anomaly_tests

    def rule(self, event):
        return event.get("action") == "anomaly"

    def alert_context(self, event):
        # TODO: Add more details to context
        return slack_alert_context(event)
