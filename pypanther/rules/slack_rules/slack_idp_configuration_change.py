from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import slack_alert_context

slack_audit_logs_idp_configuration_changed_tests: list[RuleTest] = [
    RuleTest(
        name="IDP Configuration Added",
        expected_result=True,
        log={
            "action": "idp_configuration_added",
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
            "date_create": "2022-07-28 16:48:14",
        },
    ),
    RuleTest(
        name="IDP Configuration Deleted",
        expected_result=True,
        log={
            "action": "idp_configuration_deleted",
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
            "date_create": "2022-07-28 16:48:14",
        },
    ),
    RuleTest(
        name="IDP Configuration Updated",
        expected_result=True,
        log={
            "action": "idp_prod_configuration_updated",
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
            "date_create": "2022-07-28 16:48:14",
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
class SlackAuditLogsIDPConfigurationChanged(Rule):
    id = "Slack.AuditLogs.IDPConfigurationChanged-prototype"
    display_name = "Slack IDP Configuration Changed"
    log_types = [LogType.SLACK_AUDIT_LOGS]
    tags = ["Slack", "Persistence", "Credential Access", "Modify Authentication Process"]
    reports = {"MITRE ATT&CK": ["TA0003:T1556", "TA0006:T1556"]}
    default_severity = Severity.HIGH
    default_description = "Detects changes to the identity provider (IdP) configuration for Slack organizations."
    default_reference = "https://slack.com/intl/en-gb/help/articles/115001435788-Connect-identity-provider-groups-to-your-Enterprise-Grid-org"
    summary_attributes = ["action", "p_any_ip_addresses", "p_any_emails"]
    tests = slack_audit_logs_idp_configuration_changed_tests
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
