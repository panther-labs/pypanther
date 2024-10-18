from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class AsanaWorkspaceRequireAppApprovalsDisabled(Rule):
    default_description = (
        "An Asana user turned off app approval requirements for an application type for your organization."
    )
    display_name = "Asana Workspace Require App Approvals Disabled"
    default_runbook = (
        "Confirm this user acted with valid business intent and determine whether this activity was authorized."
    )
    default_reference = "https://help.asana.com/hc/en-us/articles/14109494654875-Admin-console#:~:text=used%20by%20default-,Require%20app%20approval,-Admins%20manage%20a"
    default_severity = Severity.MEDIUM
    log_types = [LogType.ASANA_AUDIT]
    id = "Asana.Workspace.Require.App.Approvals.Disabled-prototype"

    def rule(self, event):
        new_val = event.deep_get("details", "new_value", default="<NEW_VAL_NOT_FOUND>")
        return all(
            [
                event.get("event_type", "<NO_EVENT_TYPE_FOUND>") == "workspace_require_app_approvals_of_type_changed",
                new_val == "off",
            ],
        )

    def title(self, event):
        actor_email = event.deep_get("actor", "email", default="<ACTOR_NOT_FOUND>")
        context = event.deep_get("context", "context_type", default="<APP_CONTEXT_NOT_FOUND>")
        return (
            f"Asana user [{actor_email}] disabled application approval requirements for [{context}] type applications."
        )

    tests = [
        RuleTest(
            name="Web Reqs On",
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
                "created_at": "2022-12-16 19:29:34.968",
                "details": {"new_value": "all_apps", "old_value": "off"},
                "event_category": "admin_settings",
                "event_type": "workspace_require_app_approvals_of_type_changed",
                "gid": "1234",
                "resource": {"gid": "1234", "name": "Panther Labs", "resource_type": "workspace"},
            },
        ),
        RuleTest(
            name="Web Reqs Off",
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
                "created_at": "2022-12-16 19:29:34.968",
                "details": {"new_value": "off", "old_value": "all_apps"},
                "event_category": "admin_settings",
                "event_type": "workspace_require_app_approvals_of_type_changed",
                "gid": "1234",
                "resource": {"gid": "1234", "name": "Panther Labs", "resource_type": "workspace"},
            },
        ),
    ]
