from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.slack import slack_alert_context


@panther_managed
class SlackAuditLogsPassthroughAnomaly(Rule):
    id = "Slack.AuditLogs.PassthroughAnomaly-prototype"
    display_name = "Slack Anomaly Detected"
    log_types = [LogType.SLACK_AUDIT_LOGS]
    default_severity = Severity.LOW
    reports = {"MITRE ATT&CK": ["TA0011:T1071"]}
    default_description = "Passthrough for anomalies detected by Slack"
    default_reference = "https://api.slack.com/admins/audit-logs-anomaly"
    summary_attributes = ["p_any_ip_addresses", "p_any_emails"]
    tags = ["Slack", "Command and Control", "Application Layer Protocol"]
    ELEVATED_ANOMALIES = {"excessive_malware_uploads", "session_fingerprint", "unexpected_admin_action"}

    def rule(self, event):
        return event.get("action") == "anomaly"

    def severity(self, event):
        # Return "MEDIUM" for some more serious anomalies
        reasons = event.deep_get("details", "reason", default=[])
        if set(reasons) & self.ELEVATED_ANOMALIES:
            return "MEDIUM"
        return "DEFAULT"

    def alert_context(self, event):
        context = slack_alert_context(event)
        context |= {"details": event.get("details", {}), "context": event.get("context", {})}
        return context

    tests = [
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
        RuleTest(
            name="Session Fingerprint",
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
                "date_create": "2024-08-19 13:54:53.000000000",
                "details": {
                    "action_timestamp": 1724075641026703,
                    "location": "London, UK",
                    "previous_ip_address": "",
                    "previous_ua": "",
                    "reason": ["session_fingerprint"],
                },
                "entity": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "W012J3FEWAU",
                        "name": "primary-owner",
                        "team": "T01234N56GB",
                    },
                },
                "id": "95edcb27-132a-4420-9229-783b38a16b5a",
                "p_event_time": "2024-08-19 13:54:53.000000000",
                "p_log_type": "Slack.AuditLogs",
            },
        ),
    ]
