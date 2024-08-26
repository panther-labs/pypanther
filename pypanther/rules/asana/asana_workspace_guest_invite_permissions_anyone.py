from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

asana_workspace_guest_invite_permissions_anyone_tests: list[RuleTest] = [
    RuleTest(
        name="Anyone Allowed Guest Invite",
        expected_result=True,
        log={
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
            "created_at": "2022-12-16 19:30:26.15",
            "details": {"new_value": "anyone", "old_value": "admins_only"},
            "event_category": "admin_settings",
            "event_type": "workspace_guest_invite_permissions_changed",
            "gid": "12345",
            "resource": {"gid": "12345", "name": "Example IO", "resource_type": "workspace"},
        },
    ),
    RuleTest(
        name="Other",
        expected_result=False,
        log={
            "actor": {
                "actor_type": "user",
                "email": "homer.simpson@simpsons.com",
                "gid": "1234567890",
                "name": "Homer Simpson",
            },
            "context": {
                "client_ip_address": "1.2.3.4",
                "context_type": "web",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            },
            "created_at": "2022-12-16 19:32:00.922",
            "details": {},
            "event_category": "admin_settings",
            "event_type": "workspace_form_link_authentication_required_disabled",
            "gid": "1234567890",
            "resource": {"gid": "111234", "name": "Simpsons Lab", "resource_type": "workspace"},
        },
    ),
]


@panther_managed
class AsanaWorkspaceGuestInvitePermissionsAnyone(Rule):
    default_description = "Typically inviting guests to Asana is permitted by few users. Enabling anyone to invite guests can potentially lead to unauthorized users gaining access to Asana."
    display_name = "Asana Workspace Guest Invite Permissions Anyone"
    default_reference = "https://help.asana.com/hc/en-us/articles/14109494654875-Admin-console#:~:text=Google%20SSO%20password.-,Guest%20invite%20controls,-Super%20admins%20of"
    default_severity = Severity.LOW
    log_types = [LogType.ASANA_AUDIT]
    id = "Asana.Workspace.Guest.Invite.Permissions.Anyone-prototype"
    tests = asana_workspace_guest_invite_permissions_anyone_tests

    def rule(self, event):
        return (
            event.get("event_type") == "workspace_guest_invite_permissions_changed"
            and deep_get(event, "details", "new_value") == "anyone"
        )

    def title(self, event):
        workspace = deep_get(event, "resource", "name", default="<WORKSPACE_NOT_FOUND>")
        actor = deep_get(event, "actor", "email", default="<ACTOR_NOT_FOUND>")
        return f"Asana Workspace [{workspace}] guest invite permissions changed to anyone by [{actor}]."
