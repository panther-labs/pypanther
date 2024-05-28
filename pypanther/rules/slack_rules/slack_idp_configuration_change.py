from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import slack_alert_context
from pypanther.log_types import LogType

slack_audit_logs_idp_configuration_changed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="IDP Configuration Added",
        ExpectedResult=True,
        Log={
            "action": "idp_configuration_added",
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
            "date_create": "2022-07-28 16:48:14",
        },
    ),
    PantherRuleTest(
        Name="IDP Configuration Deleted",
        ExpectedResult=True,
        Log={
            "action": "idp_configuration_deleted",
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
            "date_create": "2022-07-28 16:48:14",
        },
    ),
    PantherRuleTest(
        Name="IDP Configuration Updated",
        ExpectedResult=True,
        Log={
            "action": "idp_prod_configuration_updated",
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
            "date_create": "2022-07-28 16:48:14",
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


class SlackAuditLogsIDPConfigurationChanged(PantherRule):
    RuleID = "Slack.AuditLogs.IDPConfigurationChanged-prototype"
    DisplayName = "Slack IDP Configuration Changed"
    LogTypes = [LogType.Slack_AuditLogs]
    Tags = ["Slack", "Persistence", "Credential Access", "Modify Authentication Process"]
    Reports = {"MITRE ATT&CK": ["TA0003:T1556", "TA0006:T1556"]}
    Severity = PantherSeverity.High
    Description = (
        "Detects changes to the identity provider (IdP) configuration for Slack organizations."
    )
    Reference = "https://slack.com/intl/en-gb/help/articles/115001435788-Connect-identity-provider-groups-to-your-Enterprise-Grid-org"
    SummaryAttributes = ["action", "p_any_ip_addresses", "p_any_emails"]
    Tests = slack_audit_logs_idp_configuration_changed_tests
    IDP_CHANGE_ACTIONS = {
        "idp_configuration_added": "Slack IDP Configuration Added",
        "idp_configuration_deleted": "Slack IDP Configuration Deleted",
        "idp_prod_configuration_updated": "Slack IDP Configuration Updated",
    }

    def rule(self, event):
        return event.get("action") in self.IDP_CHANGE_ACTIONS

    def title(self, event):
        if event.get("action") in self.IDP_CHANGE_ACTIONS:
            return self.IDP_CHANGE_ACTIONS.get(event.get("action"))
        return "Slack IDP Configuration Changed"

    def alert_context(self, event):
        return slack_alert_context(event)
