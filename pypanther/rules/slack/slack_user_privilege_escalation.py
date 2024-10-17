from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.slack import slack_alert_context


@panther_managed
class SlackAuditLogsUserPrivilegeEscalation(Rule):
    id = "Slack.AuditLogs.UserPrivilegeEscalation-prototype"
    display_name = "Slack User Privilege Escalation"
    log_types = [LogType.SLACK_AUDIT_LOGS]
    tags = ["Slack", "Privilege Escalation", "Account Manipulation", "Additional Cloud Roles"]
    reports = {"MITRE ATT&CK": ["TA0004:T1098.003"]}
    default_severity = Severity.HIGH
    default_description = "Detects when a Slack user gains escalated privileges"
    default_reference = "https://slack.com/intl/en-gb/help/articles/201314026-Permissions-by-role-in-Slack"
    summary_attributes = ["p_any_ip_addresses", "p_any_emails"]
    USER_PRIV_ESC_ACTIONS = {
        "owner_transferred": "Slack Owner Transferred",
        "permissions_assigned": "Slack User Assigned Permissions",
        "role_change_to_admin": "Slack User Made Admin",
        "role_change_to_owner": "Slack User Made Owner",
    }

    def rule(self, event):
        return event.get("action") in self.USER_PRIV_ESC_ACTIONS

    def title(self, event):
        # This is the user taking the action.
        actor_username = event.deep_get("actor", "user", "name", default="<unknown-actor>")
        actor_email = event.deep_get("actor", "user", "email", default="<unknown-email>")
        # This is the user the action is taken on.
        entity_username = event.deep_get("entity", "user", "name", default="<unknown-actor>")
        entity_email = event.deep_get("entity", "user", "email", default="<unknown-email>")
        action = event.get("action")
        if action == "owner_transferred":
            return f"{self.USER_PRIV_ESC_ACTIONS[action]} from {actor_username} ({actor_email})"
        if action == "permissions_assigned":
            return f"{self.USER_PRIV_ESC_ACTIONS[action]} {entity_username} ({entity_email})"
        if action == "role_change_to_admin":
            return f"{self.USER_PRIV_ESC_ACTIONS[action]} {entity_username} ({entity_email})"
        if action == "role_change_to_owner":
            return f"{self.USER_PRIV_ESC_ACTIONS[action]} {entity_username} ({entity_email})"
        return f"Slack User Privilege Escalation event {action} on {entity_username} ({entity_email})"

    def severity(self, event):
        # Downgrade severity for users assigned permissions
        if event.get("action") == "permissions_assigned":
            return "Medium"
        return "Critical"

    def alert_context(self, event):
        return slack_alert_context(event)

    tests = [
        RuleTest(
            name="Owner Transferred",
            expected_result=True,
            log={
                "action": "owner_transferred",
                "actor": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "A012B3CDEFG",
                        "name": "username",
                        "team": "T01234N56GB",
                    },
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
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "W012J3FEWAU",
                        "name": "primary-owner",
                        "team": "T01234N56GB",
                    },
                },
            },
        ),
        RuleTest(
            name="Permissions Assigned",
            expected_result=True,
            log={
                "action": "permissions_assigned",
                "actor": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "A012B3CDEFG",
                        "name": "username",
                        "team": "T01234N56GB",
                    },
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
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "W012J3FEWAU",
                        "name": "primary-owner",
                        "team": "T01234N56GB",
                    },
                },
            },
        ),
        RuleTest(
            name="Role Changed to Admin",
            expected_result=True,
            log={
                "action": "role_change_to_admin",
                "actor": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "A012B3CDEFG",
                        "name": "username",
                        "team": "T01234N56GB",
                    },
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
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "W012J3FEWAU",
                        "name": "primary-owner",
                        "team": "T01234N56GB",
                    },
                },
            },
        ),
        RuleTest(
            name="Role Changed to Owner",
            expected_result=True,
            log={
                "action": "role_change_to_owner",
                "actor": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "A012B3CDEFG",
                        "name": "username",
                        "team": "T01234N56GB",
                    },
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
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "W012J3FEWAU",
                        "name": "primary-owner",
                        "team": "T01234N56GB",
                    },
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
