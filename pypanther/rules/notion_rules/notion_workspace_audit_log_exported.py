from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_notion_helpers import notion_alert_context
from pypanther.log_types import LogType

notion_audit_log_exported_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Other Event",
        ExpectedResult=False,
        Log={
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
            }
        },
    ),
    PantherRuleTest(
        Name="Audit Log Exported",
        ExpectedResult=True,
        Log={
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
            }
        },
    ),
]


class NotionAuditLogExported(PantherRule):
    RuleID = "Notion.Audit.Log.Exported-prototype"
    DisplayName = "Notion Audit Log Exported"
    LogTypes = [LogType.Notion_AuditLogs]
    Tags = ["Notion", "Data Security", "Data Exfiltration"]
    Severity = PantherSeverity.Medium
    Description = "A Notion User exported audit logs for your organization’s workspace."
    Runbook = "Possible Data Exfiltration. Follow up with the Notion User to determine if this was done for a valid business reason."
    Reference = "https://www.notion.so/help/audit-log#export-your-audit-log"
    Tests = notion_audit_log_exported_tests

    def rule(self, event):
        event_type = event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>")
        return event_type == "workspace.audit_log_exported"

    def title(self, event):
        user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
        workspace_id = event.deep_get("event", "workspace_id", default="<NO_WORKSPACE_ID_FOUND>")
        duration_in_days = event.deep_get(
            "event", "details", "duration_in_days", default="<NO_DURATION_IN_DAYS_FOUND>"
        )
        return f"Notion User [{user}] exported audit logs for the last {duration_in_days} days for workspace id {workspace_id}"

    def alert_context(self, event):
        return notion_alert_context(event)
