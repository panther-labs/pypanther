from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class AsanaWorkspaceOrgExport(Rule):
    default_description = "An Asana user started an org export."
    display_name = "Asana Workspace Org Export"
    default_runbook = (
        "Confirm this user acted with valid business intent and determine whether this activity was authorized."
    )
    default_reference = "https://help.asana.com/hc/en-us/articles/14139896860955-Privacy-and-security#:~:text=like%20to%20see.-,Full%20export%20of%20an%20organization,-Available%20on%20Asana"
    default_severity = Severity.MEDIUM
    log_types = [LogType.ASANA_AUDIT]
    id = "Asana.Workspace.Org.Export-prototype"

    def rule(self, event):
        return event.get("event_type", "<NO_EVENT_TYPE_FOUND>") == "workspace_export_started"

    def title(self, event):
        actor_email = event.deep_get("actor", "email", default="<ACTOR_NOT_FOUND>")
        context_type = event.deep_get("context", "context_type", default="<CONTEXT_TYPE_NOT_FOUND>")
        return f"Asana user [{actor_email}] started a [{context_type}] export for your organization."

    tests = [
        RuleTest(
            name="Web App Approvals On",
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
            name="Org Export Started",
            expected_result=True,
            log={
                "actor": {"actor_type": "user", "email": "homer@example.io", "gid": "12345", "name": "Homer Simpson"},
                "context": {
                    "client_ip_address": "12.12.12.12",
                    "context_type": "web",
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
                },
                "created_at": "2022-12-16 19:26:08.434",
                "details": {},
                "event_category": "content_export",
                "event_type": "workspace_export_started",
                "gid": "12345",
                "resource": {"gid": "12345", "name": "Example IO", "resource_type": "workspace"},
            },
        ),
    ]
