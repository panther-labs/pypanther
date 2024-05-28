from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

asana_workspace_default_session_duration_never_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Session Duration Never",
        ExpectedResult=True,
        Log={
            "actor": {
                "actor_type": "user",
                "email": "homer@example.io",
                "gid": "12345",
                "name": "Homer Simpson",
            },
            "context": {
                "client_ip_address": "12.12.12.12",
                "context_type": "web",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            },
            "created_at": "2022-12-16 19:31:13.887",
            "details": {"new_value": "never", "old_value": "14 days"},
            "event_category": "admin_settings",
            "event_type": "workspace_default_session_duration_changed",
            "gid": "12345",
            "resource": {"gid": "12345", "name": "Acme Co", "resource_type": "workspace"},
        },
    ),
    PantherRuleTest(
        Name="Other Event",
        ExpectedResult=False,
        Log={
            "actor": {
                "actor_type": "user",
                "email": "homer.simpson@panther.io",
                "gid": "12345",
                "name": "Homer Simpson",
            },
            "context": {
                "client_ip_address": "12.12.12.12",
                "context_type": "web",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            },
            "created_at": "2022-12-16 19:35:21.026",
            "details": {"new_value": "public"},
            "event_category": "access_control",
            "event_type": "team_privacy_settings_changed",
            "gid": "12345",
            "resource": {"gid": "12345", "name": "Example Team Name", "resource_type": "team"},
        },
    ),
]


class AsanaWorkspaceDefaultSessionDurationNever(PantherRule):
    Description = "An Asana workspace's default session duration (how often users need to re-authenticate) has been changed to never. "
    DisplayName = "Asana Workspace Default Session Duration Never"
    Reference = "https://help.asana.com/hc/en-us/articles/14218320495899-Manage-Session-Duration"
    Severity = PantherSeverity.Low
    LogTypes = [LogType.Asana_Audit]
    RuleID = "Asana.Workspace.Default.Session.Duration.Never-prototype"
    Tests = asana_workspace_default_session_duration_never_tests

    def rule(self, event):
        return (
            event.get("event_type") == "workspace_default_session_duration_changed"
            and deep_get(event, "details", "new_value") == "never"
        )

    def title(self, event):
        workspace = deep_get(event, "resource", "name", default="<WORKSPACE_NOT_FOUND>")
        actor = deep_get(event, "actor", "email", default="<ACTOR_NOT_FOUND>")
        return f"Asana workspace [{workspace}]'s default session duration has been set to never expire by [{actor}]."
