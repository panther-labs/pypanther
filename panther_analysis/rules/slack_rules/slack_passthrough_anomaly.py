from typing import List
from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_base_helpers import slack_alert_context

slack_audit_logs_passthrough_anomaly_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Name",
        ExpectedResult=True,
        Log={
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
    PantherRuleTest(
        Name="User Logout",
        ExpectedResult=False,
        Log={
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


class SlackAuditLogsPassthroughAnomaly(PantherRule):
    RuleID = "Slack.AuditLogs.PassthroughAnomaly-prototype"
    DisplayName = "Slack Anomaly Detected"
    Enabled = True
    LogTypes = ["Slack.AuditLogs"]
    Tags = ["Slack", "Command and Control", "Application Layer Protocol"]
    Reports = {"MITRE ATT&CK": ["TA0011:T1071"]}
    Severity = Severity.Critical
    Description = "Passthrough for anomalies detected by Slack"
    Reference = "https://slack.com/intl/en-in/blog/news/three-new-security-features-to-protect-your-digital-hq"
    DedupPeriodMinutes = 60
    Threshold = 1
    SummaryAttributes = ["p_any_ip_addresses", "p_any_emails"]
    Tests = slack_audit_logs_passthrough_anomaly_tests

    def rule(self, event):
        return event.get("action") == "anomaly"

    def alert_context(self, event):
        # TODO: Add more details to context
        return slack_alert_context(event)
