from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import slack_alert_context

slack_audit_logs_ekm_config_changed_tests: list[RuleTest] = [
    RuleTest(
        name="EKM Config Changed",
        expected_result=True,
        log={
            "action": "ekm_logging_config_set",
            "actor": {
                "type": "user",
                "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
            },
            "context": {
                "ip_address": "1.2.3.4",
                "location": {
                    "domain": "test-workspace",
                    "id": "T01234N56GB",
                    "name": "test-workspace",
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
class SlackAuditLogsEKMConfigChanged(Rule):
    id = "Slack.AuditLogs.EKMConfigChanged-prototype"
    display_name = "Slack EKM Config Changed"
    log_types = [LogType.SLACK_AUDIT_LOGS]
    tags = ["Slack", "Defense Evasion", "Impair Defenses", "Disable or Modify Cloud Logs"]
    reports = {"MITRE ATT&CK": ["TA0005:T1562.008"]}
    default_severity = Severity.HIGH
    default_description = "Detects when the logging settings for a workspace's EKM configuration has changed"
    default_reference = "https://slack.com/intl/en-gb/help/articles/360019110974-Slack-Enterprise-Key-Management"
    summary_attributes = ["p_any_ip_addresses", "p_any_emails"]
    tests = slack_audit_logs_ekm_config_changed_tests

    def rule(self, event):
        # Only alert on the `ekm_logging_config_set` action
        return event.get("action") == "ekm_logging_config_set"

    def alert_context(self, event):
        # TODO: Add details to the context
        return slack_alert_context(event)
