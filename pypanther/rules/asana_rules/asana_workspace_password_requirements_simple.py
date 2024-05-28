from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

asana_workspace_password_requirements_simple_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Simple",
        ExpectedResult=True,
        Log={
            "actor": {
                "actor_type": "user",
                "email": "homer.simpson@example.io",
                "gid": "12345",
                "name": "Homer Simpson",
            },
            "context": {
                "client_ip_address": "12.12.12.12",
                "context_type": "web",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            },
            "created_at": "2022-12-16 19:31:03.667",
            "details": {"new_value": "simple", "old_value": "strong"},
            "event_category": "admin_settings",
            "event_type": "workspace_password_requirements_changed",
            "gid": "12345",
            "resource": {
                "gid": "12345",
                "name": "Company Example IO",
                "resource_type": "workspace",
            },
        },
    ),
    PantherRuleTest(
        Name="web app approvals on",
        ExpectedResult=False,
        Log={
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
            "created_at": "2022-12-16 19:29:34.968",
            "details": {"new_value": "all_apps", "old_value": "off"},
            "event_category": "admin_settings",
            "event_type": "workspace_require_app_approvals_of_type_changed",
            "gid": "1234",
            "resource": {"gid": "1234", "name": "Panther Labs", "resource_type": "workspace"},
        },
    ),
]


class AsanaWorkspacePasswordRequirementsSimple(PantherRule):
    Description = "An asana user made your organization's password requirements less strict."
    DisplayName = "Asana Workspace Password Requirements Simple"
    Runbook = "Confirm this user acted with valid business intent and determine whether this activity was authorized."
    Reference = "https://help.asana.com/hc/en-us/articles/14075208738587-Authentication-and-access-management-options-for-paid-plans"
    Severity = PantherSeverity.Medium
    LogTypes = [LogType.Asana_Audit]
    RuleID = "Asana.Workspace.Password.Requirements.Simple-prototype"
    Tests = asana_workspace_password_requirements_simple_tests

    def rule(self, event):
        new_val = deep_get(event, "details", "new_value", default="<NEW_VAL_NOT_FOUND>")
        return all(
            [
                event.get("event_type", "<NO_EVENT_TYPE_FOUND>")
                == "workspace_password_requirements_changed",
                new_val == "simple",
            ]
        )

    def title(self, event):
        actor_email = deep_get(event, "actor", "email", default="<ACTOR_NOT_FOUND>")
        new_value = deep_get(event, "details", "new_value", default="<NEW_VAL_NOT_FOUND>")
        old_value = deep_get(event, "details", "old_value", default="<OLD_VAL_NOT_FOUND>")
        return f"Asana user [{actor_email}] changed your organization's password requirements from [{old_value}] to [{new_value}]."
