from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class AsanaServiceAccountCreated(Rule):
    default_description = "An Asana service account was created by someone in your organization."
    display_name = "Asana Service Account Created"
    default_runbook = (
        "Confirm this user acted with valid business intent and determine whether this activity was authorized."
    )
    default_reference = "https://help.asana.com/hc/en-us/articles/14217496838427-Service-Accounts"
    default_severity = Severity.MEDIUM
    log_types = [LogType.ASANA_AUDIT]
    id = "Asana.Service.Account.Created-prototype"

    def rule(self, event):
        return event.get("event_type", "<NO_EVENT_TYPE_FOUND>") == "service_account_created"

    def title(self, event):
        actor_email = event.deep_get("actor", "email", default="<ACTOR_NOT_FOUND>")
        svc_acct_name = event.deep_get("resource", "name", default="<SVC_ACCT_NAME_NOT_FOUND>")
        return f"Asana user [{actor_email}] created a new service account [{svc_acct_name}]."

    tests = [
        RuleTest(
            name="New domain created",
            expected_result=False,
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
                "details": {"new_value": "test.com"},
                "event_category": "admin_settings",
                "event_type": "workspace_associated_email_domain_added",
                "gid": "12345",
                "resource": {"gid": "12345", "name": "Example IO", "resource_type": "workspace"},
            },
        ),
        RuleTest(
            name="Slack svc acct",
            expected_result=True,
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
                "created_at": "2022-12-16 19:28:18.396",
                "details": {},
                "event_category": "apps",
                "event_type": "service_account_created",
                "gid": "12345",
                "resource": {"gid": "12345", "name": "Slack Service Account", "resource_type": "user"},
            },
        ),
        RuleTest(
            name="Datadog svc acct",
            expected_result=True,
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
                "created_at": "2022-12-16 19:28:18.396",
                "details": {},
                "event_category": "apps",
                "event_type": "service_account_created",
                "gid": "12345",
                "resource": {"gid": "12345", "name": "Datadog Service Account", "resource_type": "user"},
            },
        ),
    ]
