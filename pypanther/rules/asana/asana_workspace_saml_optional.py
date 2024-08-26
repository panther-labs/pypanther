from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

asana_workspace_saml_optional_tests: list[RuleTest] = [
    RuleTest(
        name="SAML required",
        expected_result=False,
        log={
            "actor": {
                "actor_type": "user",
                "email": "homer.simpson@example.io",
                "gid": "1234",
                "name": "Homer Simpson",
            },
            "context": {
                "client_ip_address": "12.12.12.12",
                "context_type": "web",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            },
            "created_at": "2022-12-16 19:31:36.289",
            "details": {"new_value": "required", "old_value": "optional"},
            "event_category": "admin_settings",
            "event_type": "workspace_saml_settings_changed",
            "gid": "1234",
            "resource": {"gid": "1234", "name": "example.io", "resource_type": "email_domain"},
        },
    ),
    RuleTest(
        name="SAML optional",
        expected_result=True,
        log={
            "actor": {
                "actor_type": "user",
                "email": "homer.simpson@example.io",
                "gid": "1234",
                "name": "Homer Simpson",
            },
            "context": {
                "client_ip_address": "12.12.12.12",
                "context_type": "web",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            },
            "created_at": "2022-12-16 19:31:36.289",
            "details": {"new_value": "optional", "old_value": "required"},
            "event_category": "admin_settings",
            "event_type": "workspace_saml_settings_changed",
            "gid": "1234",
            "resource": {"gid": "1234", "name": "example.io", "resource_type": "email_domain"},
        },
    ),
]


@panther_managed
class AsanaWorkspaceSAMLOptional(Rule):
    default_description = "An Asana user made SAML optional for your organization."
    display_name = "Asana Workspace SAML Optional"
    default_runbook = (
        "Confirm this user acted with valid business intent and determine whether this activity was authorized."
    )
    default_reference = "https://help.asana.com/hc/en-us/articles/14075208738587-Premium-Business-and-Enterprise-authentication#gl-saml:~:text=to%20your%20organization.-,SAML,-If%20your%20company"
    default_severity = Severity.MEDIUM
    log_types = [LogType.ASANA_AUDIT]
    id = "Asana.Workspace.SAML.Optional-prototype"
    tests = asana_workspace_saml_optional_tests

    def rule(self, event):
        old_val = deep_get(event, "details", "old_value", default="<OLD_VAL_NOT_FOUND>")
        new_val = deep_get(event, "details", "new_value", default="<NEW_VAL_NOT_FOUND>")
        return all(
            [
                event.get("event_type", "<NO_EVENT_TYPE_FOUND>") == "workspace_saml_settings_changed",
                old_val == "required",
                new_val == "optional",
            ],
        )

    def title(self, event):
        actor_email = deep_get(event, "actor", "email", default="<ACTOR_NOT_FOUND>")
        return f"Asana user [{actor_email}] made SAML optional for your organization."
