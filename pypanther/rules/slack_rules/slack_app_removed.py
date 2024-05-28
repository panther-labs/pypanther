from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get, slack_alert_context
from pypanther.log_types import LogType

slack_audit_logs_app_removed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="App Restricted",
        ExpectedResult=True,
        Log={
            "action": "app_restricted",
            "actor": {
                "type": "user",
                "user": {
                    "email": "user@example.com",
                    "id": "W012J3FEWAU",
                    "name": "primary-owner",
                    "team": "E012MH3HS94",
                },
            },
            "context": {
                "ip_address": "1.2.3.4",
                "location": {
                    "domain": "test-panther-1",
                    "id": "T01770N79GB",
                    "name": "test-workspace-1",
                    "type": "workspace",
                },
                "ua": "Go-http-client/2.0",
            },
            "date_create": "2021-06-08 22:16:15",
            "details": {"app_owner_id": "W012J3AEWAU", "is_internal_integration": True},
            "entity": {
                "app": {
                    "id": "A012F34BFEF",
                    "is_directory_approved": False,
                    "is_distributed": False,
                    "name": "app-name",
                    "scopes": ["admin"],
                },
                "type": "app",
            },
        },
    ),
    PantherRuleTest(
        Name="App Uninstalled",
        ExpectedResult=True,
        Log={
            "action": "app_uninstalled",
            "actor": {
                "type": "user",
                "user": {
                    "email": "user@example.com",
                    "id": "W012J3FEWAU",
                    "name": "primary-owner",
                    "team": "E012MH3HS94",
                },
            },
            "context": {
                "ip_address": "1.2.3.4",
                "location": {
                    "domain": "test-panther-1",
                    "id": "T01770N79GB",
                    "name": "test-workspace-1",
                    "type": "workspace",
                },
                "ua": "Go-http-client/2.0",
            },
            "date_create": "2021-06-08 22:16:15",
            "details": {"app_owner_id": "W012J3AEWAU", "is_internal_integration": True},
            "entity": {
                "app": {
                    "id": "A012F34BFEF",
                    "is_directory_approved": False,
                    "is_distributed": False,
                    "name": "app-name",
                    "scopes": ["admin"],
                },
                "type": "app",
            },
        },
    ),
    PantherRuleTest(
        Name="App removed from workspace",
        ExpectedResult=True,
        Log={
            "action": "org_app_workspace_removed",
            "actor": {
                "type": "user",
                "user": {
                    "email": "user@example.com",
                    "id": "W012J3FEWAU",
                    "name": "primary-owner",
                    "team": "E012MH3HS94",
                },
            },
            "context": {
                "ip_address": "1.2.3.4",
                "location": {
                    "domain": "test-panther-1",
                    "id": "T01770N79GB",
                    "name": "test-workspace-1",
                    "type": "workspace",
                },
                "ua": "Go-http-client/2.0",
            },
            "date_create": "2021-06-08 22:16:15",
            "details": {"app_owner_id": "W012J3AEWAU", "is_internal_integration": True},
            "entity": {
                "app": {
                    "id": "A012F34BFEF",
                    "is_directory_approved": False,
                    "is_distributed": False,
                    "name": "app-name",
                    "scopes": ["admin"],
                },
                "type": "app",
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


class SlackAuditLogsAppRemoved(PantherRule):
    RuleID = "Slack.AuditLogs.AppRemoved-prototype"
    DisplayName = "Slack App Removed"
    LogTypes = [LogType.Slack_AuditLogs]
    Tags = [
        "Slack",
        "Impact",
        "Service Stop",
        "Defense Evasion",
        "Indicator Removal",
        "Clear Persistence",
    ]
    Reports = {"MITRE ATT&CK": ["TA0040:T1489", "TA0005:T1070.009"]}
    Severity = PantherSeverity.Medium
    Description = "Detects when a Slack App has been removed"
    Reference = "https://slack.com/intl/en-gb/help/articles/360003125231-Remove-apps-and-customised-integrations-from-your-workspace"
    SummaryAttributes = ["p_any_ip_addresses", "p_any_emails"]
    Tests = slack_audit_logs_app_removed_tests
    APP_REMOVED_ACTIONS = ["app_restricted", "app_uninstalled", "org_app_workspace_removed"]

    def rule(self, event):
        return event.get("action") in self.APP_REMOVED_ACTIONS

    def title(self, event):
        return f"Slack App [{deep_get(event, 'entity', 'app', 'name')}] Removed by [{deep_get(event, 'actor', 'user', 'name')}]"

    def alert_context(self, event):
        return slack_alert_context(event)
