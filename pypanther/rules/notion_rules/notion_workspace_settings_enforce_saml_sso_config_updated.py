from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_notion_helpers import notion_alert_context
from pypanther.log_types import LogType

notion_samlsso_configuration_changed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Other Event",
        ExpectedResult=False,
        Log={
            "event": {
                "id": "...",
                "timestamp": "2023-05-15T19:14:21.031Z",
                "workspace_id": "..",
                "actor": {
                    "id": "..",
                    "object": "user",
                    "type": "person",
                    "person": {"email": "homer.simpson@yourcompany.io"},
                },
                "ip_address": "...",
                "platform": "web",
                "type": "workspace.content_exported",
                "workspace.content_exported": {},
            }
        },
    ),
    PantherRuleTest(
        Name="SAML SSO Enabled",
        ExpectedResult=True,
        Log={
            "event": {
                "id": "...",
                "timestamp": "2023-05-15T19:14:21.031Z",
                "workspace_id": "..",
                "actor": {
                    "id": "..",
                    "object": "user",
                    "type": "person",
                    "person": {"email": "homer.simpson@yourcompany.io"},
                },
                "ip_address": "...",
                "platform": "web",
                "type": "workspace.settings.enforce_saml_sso_config_updated",
                "workspace.settings.enforce_saml_sso_config_updated": {"state": "enabled"},
            }
        },
    ),
    PantherRuleTest(
        Name="SAML SSO Disabled",
        ExpectedResult=True,
        Log={
            "event": {
                "id": "...",
                "timestamp": "2023-05-15T19:14:21.031Z",
                "workspace_id": "..",
                "actor": {
                    "id": "..",
                    "object": "user",
                    "type": "person",
                    "person": {"email": "homer.simpson@yourcompany.io"},
                },
                "ip_address": "...",
                "platform": "web",
                "type": "workspace.settings.enforce_saml_sso_config_updated",
                "workspace.settings.enforce_saml_sso_config_updated": {"state": "disabled"},
            }
        },
    ),
]


class NotionSAMLSSOConfigurationChanged(PantherRule):
    RuleID = "Notion.SAML.SSO.Configuration.Changed-prototype"
    DisplayName = "Notion SAML SSO Configuration Changed"
    LogTypes = [LogType.Notion_AuditLogs]
    Tags = ["Notion", "Identity & Access Management", "Credential Security"]
    Severity = PantherSeverity.High
    Description = (
        "A Notion User changed settings to enforce SAML SSO configurations for your organization."
    )
    Runbook = "Follow up with the Notion User to determine if this was done for a valid business reason and to ensure these settings get re-enabled quickly for best security practices."
    Reference = "https://www.notion.so/help/saml-sso-configuration"
    Tests = notion_samlsso_configuration_changed_tests

    def rule(self, event):
        return (
            event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>")
            == "workspace.settings.enforce_saml_sso_config_updated"
        )

    def title(self, event):
        user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
        workspace_id = event.deep_get("event", "workspace_id", default="<NO_WORKSPACE_ID_FOUND>")
        state = deep_get(
            event,
            "event",
            "workspace.settings.enforce_saml_sso_config_updated",
            "state",
            default="<NO_STATE_FOUND>",
        )
        if state == "enabled":
            return f"Notion User [{user}] updated settings to enable SAML SSO config from workspace id {workspace_id}"
        return f"Notion User [{user}] updated settings to disable SAML SSO config from workspace id {workspace_id}"

    def severity(self, event):
        state = deep_get(
            event,
            "event",
            "workspace.settings.enforce_saml_sso_config_updated",
            "state",
            default="<NO_STATE_FOUND>",
        )
        if state == "enabled":
            return "INFO"
        return "HIGH"

    def alert_context(self, event):
        return notion_alert_context(event)
