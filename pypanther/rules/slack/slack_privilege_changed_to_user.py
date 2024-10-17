from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.slack import slack_alert_context


@panther_managed
class SlackAuditLogsUserPrivilegeChangedToUser(Rule):
    id = "Slack.AuditLogs.UserPrivilegeChangedToUser-prototype"
    display_name = "Slack User Privileges Changed to User"
    log_types = [LogType.SLACK_AUDIT_LOGS]
    tags = ["Slack", "Impact", "Account Access Removal"]
    reports = {"MITRE ATT&CK": ["TA0040:T1531"]}
    default_severity = Severity.MEDIUM
    default_description = "Detects when a Slack account is changed to User from an elevated role."
    default_reference = "https://slack.com/intl/en-gb/help/articles/360018112273-Types-of-roles-in-Slack"
    summary_attributes = ["p_any_ip_addresses", "p_any_emails"]

    def rule(self, event):
        return event.get("action") == "role_change_to_user"

    def title(self, event):
        username = event.deep_get("entity", "user", "name", default="<unknown-entity>")
        email = event.deep_get("entity", "user", "email", default="<unknown-email>")
        return f"Slack {username}'s ({email}) role changed to User"

    def alert_context(self, event):
        return slack_alert_context(event)

    tests = [
        RuleTest(
            name="Role Changed to User",
            expected_result=True,
            log={
                "action": "role_change_to_user",
                "actor": {
                    "type": "user",
                    "user": {
                        "email": "slack-enterprise-example@example.io",
                        "id": "W015MH5MPGE",
                        "name": "primary-owner",
                        "team": "T017E0M3CQ4",
                    },
                },
                "context": {
                    "ip_address": "12.12.12.12",
                    "location": {
                        "domain": "example-workspace-domain",
                        "id": "T017E0M3CQ4",
                        "name": "example-workspace",
                        "type": "workspace",
                    },
                    "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                },
                "date_create": "2023-02-24 18:34:18",
                "entity": {
                    "type": "user",
                    "user": {
                        "email": "example-account@example.com",
                        "id": "U04R70MM40K",
                        "name": "Example Account",
                        "team": "T017E0M3CQ4",
                    },
                },
                "id": "4c248a02-119c-4f76-ba5d-a96767d45be8",
            },
        ),
        RuleTest(
            name="Role Changed to Admin",
            expected_result=False,
            log={
                "action": "role_change_to_admin",
                "actor": {
                    "type": "user",
                    "user": {
                        "email": "slack-enterprise-example@example.io",
                        "id": "W015MH5MPGE",
                        "name": "primary-owner",
                        "team": "T017E0M3CQ4",
                    },
                },
                "context": {
                    "ip_address": "12.12.12.12",
                    "location": {
                        "domain": "example-workspace-domain",
                        "id": "T017E0M3CQ4",
                        "name": "example-workspace",
                        "type": "workspace",
                    },
                    "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                },
                "date_create": "2023-02-24 18:33:21",
                "entity": {
                    "type": "user",
                    "user": {
                        "email": "example-account@example.com",
                        "id": "U04R70MM40K",
                        "name": "Example Account",
                        "team": "T017E0M3CQ4",
                    },
                },
                "id": "1ad8fa51-f18e-450a-8e18-cfe31278be96",
            },
        ),
    ]
