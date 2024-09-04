from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.notion import notion_alert_context


@panther_managed
class NotionAuditLogExported(Rule):
    id = "Notion.Audit.Log.Exported-prototype"
    display_name = "Notion Audit Log Exported"
    log_types = [LogType.NOTION_AUDIT_LOGS]
    tags = ["Notion", "Data Security", "Data Exfiltration"]
    default_severity = Severity.MEDIUM
    default_description = "A Notion User exported audit logs for your organization’s workspace."
    default_runbook = "Possible Data Exfiltration. Follow up with the Notion User to determine if this was done for a valid business reason."
    default_reference = "https://www.notion.so/help/audit-log#export-your-audit-log"

    def rule(self, event):
        event_type = event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>")
        return event_type == "workspace.audit_log_exported"

    def title(self, event):
        user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
        workspace_id = event.deep_get("event", "workspace_id", default="<NO_WORKSPACE_ID_FOUND>")
        duration_in_days = event.deep_get("event", "details", "duration_in_days", default="<NO_DURATION_IN_DAYS_FOUND>")
        return f"Notion User [{user}] exported audit logs for the last {duration_in_days} days for workspace id {workspace_id}"

    def alert_context(self, event):
        return notion_alert_context(event)

    tests = [
        RuleTest(
            name="Other Event",
            expected_result=False,
            log={
                "event": {
                    "id": "...",
                    "timestamp": "2023-05-15T19:14:21.031Z",
                    "workspace_id": "..",
                    "actor": {
                        "id": "..",
                        "object": "user",
                        "type": "person",
                        "person": {"email": "homer.simpson@yourcompany.io"},
                    },
                    "ip_address": "...",
                    "platform": "web",
                    "type": "workspace.content_exported",
                    "workspace.content_exported": {},
                },
            },
        ),
        RuleTest(
            name="Audit Log Exported",
            expected_result=True,
            log={
                "event": {
                    "id": "...",
                    "timestamp": "2023-05-15T19:14:21.031Z",
                    "workspace_id": "..",
                    "actor": {
                        "object": "user",
                        "id": "..",
                        "type": "person",
                        "person": {"email": "homer.simpson@yourcompany.io"},
                    },
                    "ip_address": "...",
                    "platform": "web",
                    "type": "workspace.audit_log_exported",
                    "details": {"duration_in_days": 30},
                },
            },
        ),
    ]
