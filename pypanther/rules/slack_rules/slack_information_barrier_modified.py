from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import slack_alert_context
from pypanther.log_types import LogType

slack_audit_logs_information_barrier_modified_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Information Barrier Deleted",
        ExpectedResult=True,
        Log={
            "action": "barrier_deleted",
            "actor": {
                "type": "user",
                "user": {
                    "email": "user@example.com",
                    "id": "A012B3CDEFG",
                    "name": "username",
                    "team": "T01234N56GB",
                },
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
    PantherRuleTest(
        Name="Information Barrier Updated",
        ExpectedResult=True,
        Log={
            "action": "barrier_updated",
            "actor": {
                "type": "user",
                "user": {
                    "email": "user@example.com",
                    "id": "A012B3CDEFG",
                    "name": "username",
                    "team": "T01234N56GB",
                },
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


class SlackAuditLogsInformationBarrierModified(PantherRule):
    RuleID = "Slack.AuditLogs.InformationBarrierModified-prototype"
    DisplayName = "Slack Information Barrier Modified"
    LogTypes = [LogType.Slack_AuditLogs]
    Tags = ["Slack", "Defense Evasion", "Impair Defenses", "Disable or Modify Tools"]
    Reports = {"MITRE ATT&CK": ["TA0005:T1562.001"]}
    Severity = PantherSeverity.Medium
    Description = "Detects when a Slack information barrier is deleted/updated"
    Reference = "https://slack.com/intl/en-gb/help/articles/360056171734-Create-information-barriers-in-Slack"
    SummaryAttributes = ["action", "p_any_ip_addresses", "p_any_emails"]
    Tests = slack_audit_logs_information_barrier_modified_tests
    INFORMATION_BARRIER_ACTIONS = {
        "barrier_deleted": "Slack Information Barrier Deleted",
        "barrier_updated": "Slack Information Barrier Updated",
    }

    def rule(self, event):
        return event.get("action") in self.INFORMATION_BARRIER_ACTIONS

    def title(self, event):
        if event.get("action") in self.INFORMATION_BARRIER_ACTIONS:
            return self.INFORMATION_BARRIER_ACTIONS.get(event.get("action"))
        return "Slack Information Barrier Modified"

    def alert_context(self, event):
        return slack_alert_context(event)
