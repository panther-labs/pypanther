from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import slack_alert_context
from pypanther.log_types import LogType

slack_audit_logs_org_created_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Organization Created",
        ExpectedResult=True,
        Log={
            "action": "organization_created",
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
        Name="Organization Deleted",
        ExpectedResult=False,
        Log={
            "action": "organization_deleted",
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
]


class SlackAuditLogsOrgCreated(PantherRule):
    RuleID = "Slack.AuditLogs.OrgCreated-prototype"
    DisplayName = "Slack Organization Created"
    LogTypes = [LogType.Slack_AuditLogs]
    Tags = ["Slack", "Persistence", "Create Account"]
    Reports = {"MITRE ATT&CK": ["TA0003:T1136"]}
    Severity = PantherSeverity.Low
    Description = "Detects when a Slack organization is created"
    Reference = "https://slack.com/intl/en-gb/help/articles/206845317-Create-a-Slack-workspace"
    SummaryAttributes = ["p_any_ip_addresses", "p_any_emails"]
    Tests = slack_audit_logs_org_created_tests

    def rule(self, event):
        return event.get("action") == "organization_created"

    def alert_context(self, event):
        return slack_alert_context(event)
