from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get, slack_alert_context

slack_audit_logs_app_access_expanded_tests: list[RuleTest] = [
    RuleTest(
        name="App Scopes Expanded",
        expected_result=True,
        log={
            "action": "app_scopes_expanded",
            "actor": {
                "type": "user",
                "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
            },
            "context": {
                "ip_address": "1.2.3.4",
                "location": {
                    "domain": "test-workspace",
                    "id": "T01234N56GB",
                    "name": "test-workspace",
                    "type": "workspace",
                },
                "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
            },
            "date_create": "2022-07-28 16:48:14",
            "details": {
                "granular_bot_token": True,
                "is_internal_integration": False,
                "is_token_rotation_enabled_app": False,
                "new_scopes": [
                    "app_mentions:read",
                    "channels:join",
                    "channels:read",
                    "chat:write",
                    "chat:write.public",
                    "team:read",
                    "users:read",
                    "im:history",
                    "groups:read",
                    "reactions:write",
                    "groups:history",
                    "channels:history",
                ],
                "previous_scopes": [
                    "app_mentions:read",
                    "commands",
                    "channels:join",
                    "channels:read",
                    "chat:write",
                    "chat:write.public",
                    "users:read",
                    "groups:read",
                    "reactions:write",
                    "groups:history",
                    "channels:history",
                ],
            },
            "entity": {
                "type": "workspace",
                "workspace": {"domain": "test-workspace-1", "id": "T01234N56GB", "name": "test-workspace-1"},
            },
            "id": "9d9b76ce-47bb-4838-a96a-1b5fd4d1b564",
        },
    ),
    RuleTest(
        name="App Resources Added",
        expected_result=True,
        log={
            "action": "app_resources_added",
            "actor": {
                "type": "user",
                "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
            },
            "context": {
                "ip_address": "1.2.3.4",
                "location": {
                    "domain": "test-workspace",
                    "id": "T01234N56GB",
                    "name": "test-workspace",
                    "type": "workspace",
                },
                "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
            },
            "entity": {
                "type": "workspace",
                "workspace": {"domain": "test-workspace-1", "id": "T01234N56GB", "name": "test-workspace-1"},
            },
            "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
        },
    ),
    RuleTest(
        name="App Resources Granted",
        expected_result=True,
        log={
            "action": "app_resources_granted",
            "actor": {
                "type": "user",
                "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
            },
            "context": {
                "ip_address": "1.2.3.4",
                "location": {
                    "domain": "test-workspace",
                    "id": "T01234N56GB",
                    "name": "test-workspace",
                    "type": "workspace",
                },
                "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
            },
            "date_create": "2022-07-28 16:48:14",
            "details": {
                "export_end_ts": "2022-07-28 09:48:12",
                "export_start_ts": "2022-07-27 09:48:12",
                "export_type": "STANDARD",
            },
            "entity": {
                "type": "workspace",
                "workspace": {"domain": "test-workspace-1", "id": "T01234N56GB", "name": "test-workspace-1"},
            },
            "id": "9d9b76ce-47bb-4838-a96a-1b5fd4d1b564",
        },
    ),
    RuleTest(
        name="Bot Token Upgraded",
        expected_result=True,
        log={
            "action": "bot_token_upgraded",
            "actor": {
                "type": "user",
                "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
            },
            "context": {
                "ip_address": "1.2.3.4",
                "location": {
                    "domain": "test-workspace",
                    "id": "T01234N56GB",
                    "name": "test-workspace",
                    "type": "workspace",
                },
                "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
            },
            "entity": {
                "type": "workspace",
                "workspace": {"domain": "test-workspace-1", "id": "T01234N56GB", "name": "test-workspace-1"},
            },
            "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
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


@panther_managed
class SlackAuditLogsAppAccessExpanded(Rule):
    id = "Slack.AuditLogs.AppAccessExpanded-prototype"
    display_name = "Slack App Access Expanded"
    log_types = [LogType.SLACK_AUDIT_LOGS]
    tags = ["Slack", "Privilege Escalation", "Account Manipulation"]
    reports = {"MITRE ATT&CK": ["TA0004:T1098"]}
    default_severity = Severity.MEDIUM
    default_description = "Detects when a Slack App has had its permission scopes expanded"
    default_reference = "https://slack.com/intl/en-gb/help/articles/1500009181142-Manage-app-settings-and-permissions"
    summary_attributes = ["action", "p_any_ip_addresses", "p_any_emails"]
    tests = slack_audit_logs_app_access_expanded_tests
    ACCESS_EXPANDED_ACTIONS = [
        "app_scopes_expanded",
        "app_resources_added",
        "app_resources_granted",
        "bot_token_upgraded",
    ]

    def rule(self, event):
        return event.get("action") in self.ACCESS_EXPANDED_ACTIONS

    def title(self, event):
        return f"Slack App [{deep_get(event, 'entity', 'app', 'name')}] Access Expanded by [{deep_get(event, 'actor', 'user', 'name')}]"

    def alert_context(self, event):
        context = slack_alert_context(event)
        # Diff previous and new scopes
        new_scopes = deep_get(event, "details", "new_scopes", default=[])
        prv_scopes = deep_get(event, "details", "previous_scopes", default=[])
        context["scopes_added"] = [x for x in new_scopes if x not in prv_scopes]
        context["scoped_removed"] = [x for x in prv_scopes if x not in new_scopes]
        return context

    def severity(self, event):
        # Used to escalate to High/Critical if the app is granted admin privileges
        # May want to escalate to "Critical" depending on security posture
        if "admin" in deep_get(event, "entity", "app", "scopes", default=[]):
            return "High"
        # Fallback method in case the admin scope is not directly mentioned in entity for whatever
        if "admin" in deep_get(event, "details", "new_scope", default=[]):
            return "High"
        if "admin" in deep_get(event, "details", "bot_scopes", default=[]):
            return "High"
        return "Medium"
