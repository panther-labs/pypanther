from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.notion import notion_alert_context


@panther_managed
class NotionLogin(Rule):
    id = "Notion.Login-prototype"
    display_name = "Signal - Notion Login"
    create_alert = False
    log_types = [LogType.NOTION_AUDIT_LOGS]
    tags = ["Notion", "Identity & Access Management"]
    default_severity = Severity.INFO
    default_description = "A Notion User logged in."
    default_reference = "https://www.notion.so/help/account-settings"

    def rule(self, event):
        if event.deep_walk("event", "type") == "user.login":
            return True
        return False

    def title(self, event):
        user_email = event.deep_walk("event", "actor", "person", "email", default="UNKNOWN EMAIL")
        return f"Notion User [{user_email}] logged in."

    def alert_context(self, event):
        context = notion_alert_context(event)
        context["login_timestamp"] = event.get("p_event_time")
        context["actor_id"] = event.deep_walk("event", "actor", "id")
        return context

    tests = [
        RuleTest(
            name="Login event",
            expected_result=True,
            log={
                "event": {
                    "actor": {
                        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                        "object": "user",
                        "person": {"email": "aragorn.elessar@lotr.com"},
                        "type": "person",
                    },
                    "details": {"authType": "email"},
                    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "ip_address": "192.168.100.100",
                    "platform": "web",
                    "timestamp": "2023-06-12 21:40:28.690000000",
                    "type": "user.login",
                    "workspace_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                },
                "p_event_time": "2023-06-12 21:40:28.690000000",
                "p_log_type": "Notion.AuditLogs",
                "p_parse_time": "2023-06-12 22:53:51.602223297",
                "p_row_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "p_schema_version": 0,
                "p_source_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "p_source_label": "Notion Logs",
            },
        ),
        RuleTest(
            name="Not login event",
            expected_result=False,
            log={
                "event": {
                    "actor": {
                        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                        "object": "user",
                        "person": {"email": "aragorn.elessar@lotr.com"},
                        "type": "person",
                    },
                    "details": {"authType": "email"},
                    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "ip_address": "192.168.100.100",
                    "platform": "web",
                    "timestamp": "2023-06-12 21:40:28.690000000",
                    "type": "user.settings.login_method.email_updated",
                    "workspace_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                },
                "p_event_time": "2023-06-12 21:40:28.690000000",
                "p_log_type": "Notion.AuditLogs",
                "p_parse_time": "2023-06-12 22:53:51.602223297",
                "p_row_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "p_schema_version": 0,
                "p_source_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "p_source_label": "Notion Logs",
            },
        ),
    ]
