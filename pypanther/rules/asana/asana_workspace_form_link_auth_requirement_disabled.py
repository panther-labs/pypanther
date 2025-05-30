from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class AsanaWorkspaceFormLinkAuthRequirementDisabled(Rule):
    default_description = "An Asana Workspace Form Link is a unique URL that allows you to create a task directly within a specific Workspace or Project in Asana, using a web form. Disabling authentication requirements may allow unauthorized users to create tasks. "
    display_name = "Asana Workspace Form Link Auth Requirement Disabled"
    default_reference = "https://help.asana.com/hc/en-us/articles/14111697664923-Forms-access-permissions#:~:text=SSO%2C%20SAML%2C%20or-,no%20authentication%20method,-).%20If%20no%20authentication"
    default_severity = Severity.LOW
    log_types = [LogType.ASANA_AUDIT]
    id = "Asana.Workspace.Form.Link.Auth.Requirement.Disabled-prototype"

    def rule(self, event):
        return event.get("event_type") == "workspace_form_link_authentication_required_disabled"

    def title(self, event):
        workspace = event.deep_get("resource", "name", default="<WORKSPACE_NOT_FOUND>")
        actor = event.deep_get("actor", "email", default="<ACTOR_NOT_FOUND>")
        return f"Asana Workspace [{workspace}] Form Link Auth Requirement  was disabled by [{actor}]."

    tests = [
        RuleTest(
            name="form auth requirement disabled",
            expected_result=True,
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
        RuleTest(
            name="other",
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
            },
        ),
    ]
