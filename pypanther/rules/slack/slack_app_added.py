from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.slack import slack_alert_context


@panther_managed
class SlackAuditLogsAppAdded(Rule):
    id = "Slack.AuditLogs.AppAdded-prototype"
    display_name = "Slack App Added"
    log_types = [LogType.SLACK_AUDIT_LOGS]
    tags = ["Slack", "Persistence", "Server Software Component"]
    reports = {"MITRE ATT&CK": ["TA0003:T1505"]}
    default_severity = Severity.MEDIUM
    default_description = "Detects when a Slack App has been added to a workspace"
    default_reference = "https://slack.com/intl/en-gb/help/articles/202035138-Add-apps-to-your-Slack-workspace"
    summary_attributes = ["p_any_ip_addresses", "p_any_emails"]
    APP_ADDED_ACTIONS = ["app_approved", "app_installed", "org_app_workspace_added"]

    def rule(self, event):
        return event.get("action") in self.APP_ADDED_ACTIONS

    def title(self, event):
        return f"Slack App [{event.deep_get('entity', 'app', 'name')}] Added by [{event.deep_get('actor', 'user', 'name')}]"

    def alert_context(self, event):
        context = slack_alert_context(event)
        context["scopes"] = event.deep_get("entity", "scopes")
        return context

    def severity(self, event):
        # Used to escalate to High/Critical if the app is granted admin privileges
        # May want to escalate to "Critical" depending on security posture
        if "admin" in event.deep_get("entity", "app", "scopes", default=[]):
            return "High"
        # Fallback method in case the admin scope is not directly mentioned in entity for whatever
        if "admin" in event.deep_get("details", "new_scope", default=[]):
            return "High"
        if "admin" in event.deep_get("details", "bot_scopes", default=[]):
            return "High"
        return "Medium"

    tests = [
        RuleTest(
            name="App added to workspace - Admin not in app scopes",
            expected_result=True,
            log={
                "action": "app_installed",
                "actor": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "W012J3FEWAU",
                        "name": "primary-owner",
                        "team": "E012MH3HS94",
                    },
                },
                "context": {
                    "ip_address": "1.2.3.4",
                    "location": {
                        "domain": "test-panther-1",
                        "id": "T01770N79GB",
                        "name": "test-workspace-1",
                        "type": "workspace",
                    },
                    "ua": "Go-http-client/2.0",
                },
                "date_create": "2021-06-08 22:16:15",
                "details": {"is_internal_integration": False, "is_token_rotation_enabled_app": False},
                "entity": {
                    "app": {
                        "id": "A049JV0H0KC",
                        "is_directory_approved": True,
                        "is_distributed": True,
                        "name": "Notion",
                        "scopes": [
                            "channels:history",
                            "channels:read",
                            "chat:write",
                            "groups:read",
                            "groups:write",
                            "im:read",
                            "mpim:read",
                            "groups:history",
                            "im:history",
                            "mpim:history",
                        ],
                    },
                    "type": "app",
                },
            },
        ),
        RuleTest(
            name="App Approved",
            expected_result=True,
            log={
                "action": "app_installed",
                "actor": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "W012J3FEWAU",
                        "name": "primary-owner",
                        "team": "E012MH3HS94",
                    },
                },
                "context": {
                    "ip_address": "1.2.3.4",
                    "location": {
                        "domain": "test-panther-1",
                        "id": "T01770N79GB",
                        "name": "test-workspace-1",
                        "type": "workspace",
                    },
                    "ua": "Go-http-client/2.0",
                },
                "date_create": "2021-06-08 22:16:15",
                "details": {"app_owner_id": "W012J3AEWAU", "is_internal_integration": True},
                "entity": {
                    "app": {
                        "id": "A012F34BFEF",
                        "is_directory_approved": False,
                        "is_distributed": False,
                        "name": "app-name",
                        "scopes": ["admin"],
                    },
                    "type": "app",
                },
            },
        ),
        RuleTest(
            name="App Installed",
            expected_result=True,
            log={
                "action": "app_installed",
                "actor": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "W012J3FEWAU",
                        "name": "primary-owner",
                        "team": "E012MH3HS94",
                    },
                },
                "context": {
                    "ip_address": "1.2.3.4",
                    "location": {
                        "domain": "test-panther-1",
                        "id": "T01770N79GB",
                        "name": "test-workspace-1",
                        "type": "workspace",
                    },
                    "ua": "Go-http-client/2.0",
                },
                "date_create": "2021-06-08 22:16:15",
                "details": {"app_owner_id": "W012J3AEWAU", "is_internal_integration": True},
                "entity": {
                    "app": {
                        "id": "A012F34BFEF",
                        "is_directory_approved": False,
                        "is_distributed": False,
                        "name": "app-name",
                        "scopes": ["admin"],
                    },
                    "type": "app",
                },
            },
        ),
        RuleTest(
            name="App added to workspace",
            expected_result=True,
            log={
                "action": "app_installed",
                "actor": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "W012J3FEWAU",
                        "name": "primary-owner",
                        "team": "E012MH3HS94",
                    },
                },
                "context": {
                    "ip_address": "1.2.3.4",
                    "location": {
                        "domain": "test-panther-1",
                        "id": "T01770N79GB",
                        "name": "test-workspace-1",
                        "type": "workspace",
                    },
                    "ua": "Go-http-client/2.0",
                },
                "date_create": "2021-06-08 22:16:15",
                "details": {"app_owner_id": "W012J3AEWAU", "is_internal_integration": True},
                "entity": {
                    "app": {
                        "id": "A012F34BFEF",
                        "is_directory_approved": False,
                        "is_distributed": False,
                        "name": "app-name",
                        "scopes": ["admin"],
                    },
                    "type": "app",
                },
            },
        ),
        RuleTest(
            name="User Logout",
            expected_result=False,
            log={
                "action": "user_logout",
                "actor": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "W012J3FEWAU",
                        "name": "primary-owner",
                        "team": "T01234N56GB",
                    },
                },
                "context": {
                    "ip_address": "1.2.3.4",
                    "location": {
                        "domain": "test-workspace-1",
                        "id": "T01234N56GB",
                        "name": "test-workspace-1",
                        "type": "workspace",
                    },
                    "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                },
                "date_create": "2022-07-28 15:22:32",
                "entity": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "W012J3FEWAU",
                        "name": "primary-owner",
                        "team": "T01234N56GB",
                    },
                },
                "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
            },
        ),
    ]
