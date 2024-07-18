from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_asana_helpers import asana_alert_context
from pypanther.helpers.panther_base_helpers import deep_get

asana_workspace_new_admin_tests: list[RuleTest] = [
    RuleTest(
        name="Team made public",
        expected_result=False,
        log={
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
            "p_log_type": "Asana.Audit",
        },
    ),
    RuleTest(
        name="New Workspace Admin",
        expected_result=True,
        log={
            "p_log_type": "Asana.Audit",
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
            "created_at": "2022-12-16 19:32:22.377",
            "details": {
                "group": {"gid": "1234", "name": "Workspace Name", "resource_type": "workspace"},
                "new_value": "domain_admin",
                "old_value": "member",
            },
            "event_category": "roles",
            "event_type": "user_workspace_admin_role_changed",
            "gid": "1234",
            "resource": {"email": "target@example.io", "gid": "1234", "name": "Bart Simpson", "resource_type": "user"},
        },
    ),
]


@panther_managed
class AsanaWorkspaceNewAdmin(Rule):
    default_description = "Admin role was granted to the user who previously did not have admin permissions"
    display_name = "Asana Workspace New Admin"
    default_reference = "https://help.asana.com/hc/en-us/articles/14141552580635-Admin-and-super-admin-roles-in-Asana"
    default_severity = Severity.HIGH
    log_types = [LogType.ASANA_AUDIT]
    id = "Asana.Workspace.New.Admin-prototype"
    tests = asana_workspace_new_admin_tests

    def rule(self, event):
        new = deep_get(event, "details", "new_value", default="")
        old = deep_get(event, "details", "old_value", default="")
        return all([event.get("event_type") == "user_workspace_admin_role_changed", "admin" in new, "admin" not in old])

    def title(self, event):
        a_c = asana_alert_context(event)
        w_s = deep_get(event, "details", "group", "name", default="<WS_NAME_NOT_FOUND>")
        return (
            f"Asana user [{a_c.get('resource_name')}] was made an admin in workspace [{w_s}] by [{a_c.get('actor')}]."
        )

    def alert_context(self, event):
        return asana_alert_context(event)
