from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import slack_alert_context

slack_audit_logs_service_owner_transferred_tests: list[RuleTest] = [
    RuleTest(
        name="Service Owner Transferred",
        expected_result=True,
        log={
            "action": "service_owner_transferred",
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
class SlackAuditLogsServiceOwnerTransferred(Rule):
    id = "Slack.AuditLogs.ServiceOwnerTransferred-prototype"
    display_name = "Slack Service Owner Transferred"
    log_types = [LogType.SLACK_AUDIT_LOGS]
    tags = [
        "Slack",
        "Defense Evasion",
        "File and Directory Permissions Modification",
        "Persistence",
        "Account Manipulation",
        "Impact",
        "Account Access Removal",
    ]
    reports = {"MITRE ATT&CK": ["TA0005:T1222", "TA0003:T1098", "TA0040:T1531"]}
    default_severity = Severity.CRITICAL
    default_description = "Detects transferring of service owner on request from primary owner"
    default_reference = "https://slack.com/intl/en-gb/help/articles/204401633-Transfer-ownership-of-a-workspace-or-org"
    summary_attributes = ["p_any_ip_addresses", "p_any_emails"]
    tests = slack_audit_logs_service_owner_transferred_tests

    def rule(self, event):
        return event.get("action") == "service_owner_transferred"

    def alert_context(self, event):
        return slack_alert_context(event)
