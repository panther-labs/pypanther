from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_notion_helpers import notion_alert_context

notion_samlsso_configuration_changed_tests: list[RuleTest] = [
    RuleTest(
        name="Other Event",
        expected_result=False,
        log={
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
            },
        },
    ),
    RuleTest(
        name="SAML SSO Enabled",
        expected_result=True,
        log={
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
            },
        },
    ),
    RuleTest(
        name="SAML SSO Disabled",
        expected_result=True,
        log={
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
            },
        },
    ),
]


@panther_managed
class NotionSAMLSSOConfigurationChanged(Rule):
    id = "Notion.SAML.SSO.Configuration.Changed-prototype"
    display_name = "Notion SAML SSO Configuration Changed"
    log_types = [LogType.NOTION_AUDIT_LOGS]
    tags = ["Notion", "Identity & Access Management", "Credential Security"]
    default_severity = Severity.HIGH
    default_description = "A Notion User changed settings to enforce SAML SSO configurations for your organization."
    default_runbook = "Follow up with the Notion User to determine if this was done for a valid business reason and to ensure these settings get re-enabled quickly for best security practices."
    default_reference = "https://www.notion.so/help/saml-sso-configuration"
    tests = notion_samlsso_configuration_changed_tests

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
