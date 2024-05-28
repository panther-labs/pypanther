from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get, slack_alert_context
from pypanther.log_types import LogType

slack_audit_logs_user_privilege_changed_to_user_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Role Changed to User",
        ExpectedResult=True,
        Log={
            "action": "role_change_to_user",
            "actor": {
                "type": "user",
                "user": {
                    "email": "slack-enterprise-example@example.io",
                    "id": "W015MH5MPGE",
                    "name": "primary-owner",
                    "team": "T017E0M3CQ4",
                },
            },
            "context": {
                "ip_address": "12.12.12.12",
                "location": {
                    "domain": "example-workspace-domain",
                    "id": "T017E0M3CQ4",
                    "name": "example-workspace",
                    "type": "workspace",
                },
                "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
            },
            "date_create": "2023-02-24 18:34:18",
            "entity": {
                "type": "user",
                "user": {
                    "email": "example-account@example.com",
                    "id": "U04R70MM40K",
                    "name": "Example Account",
                    "team": "T017E0M3CQ4",
                },
            },
            "id": "4c248a02-119c-4f76-ba5d-a96767d45be8",
        },
    ),
    PantherRuleTest(
        Name="Role Changed to Admin",
        ExpectedResult=False,
        Log={
            "action": "role_change_to_admin",
            "actor": {
                "type": "user",
                "user": {
                    "email": "slack-enterprise-example@example.io",
                    "id": "W015MH5MPGE",
                    "name": "primary-owner",
                    "team": "T017E0M3CQ4",
                },
            },
            "context": {
                "ip_address": "12.12.12.12",
                "location": {
                    "domain": "example-workspace-domain",
                    "id": "T017E0M3CQ4",
                    "name": "example-workspace",
                    "type": "workspace",
                },
                "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
            },
            "date_create": "2023-02-24 18:33:21",
            "entity": {
                "type": "user",
                "user": {
                    "email": "example-account@example.com",
                    "id": "U04R70MM40K",
                    "name": "Example Account",
                    "team": "T017E0M3CQ4",
                },
            },
            "id": "1ad8fa51-f18e-450a-8e18-cfe31278be96",
        },
    ),
]


class SlackAuditLogsUserPrivilegeChangedToUser(PantherRule):
    RuleID = "Slack.AuditLogs.UserPrivilegeChangedToUser-prototype"
    DisplayName = "Slack User Privileges Changed to User"
    LogTypes = [LogType.Slack_AuditLogs]
    Tags = ["Slack", "Impact", "Account Access Removal"]
    Reports = {"MITRE ATT&CK": ["TA0040:T1531"]}
    Severity = PantherSeverity.Medium
    Description = "Detects when a Slack account is changed to User from an elevated role."
    Reference = "https://slack.com/intl/en-gb/help/articles/360018112273-Types-of-roles-in-Slack"
    SummaryAttributes = ["p_any_ip_addresses", "p_any_emails"]
    Tests = slack_audit_logs_user_privilege_changed_to_user_tests

    def rule(self, event):
        return event.get("action") == "role_change_to_user"

    def title(self, event):
        username = deep_get(event, "entity", "user", "name", default="<unknown-entity>")
        email = deep_get(event, "entity", "user", "email", default="<unknown-email>")
        return f"Slack {username}'s ({email}) role changed to User"

    def alert_context(self, event):
        return slack_alert_context(event)
