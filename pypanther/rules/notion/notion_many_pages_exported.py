from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.notion import notion_alert_context


@panther_managed
class NotionManyPagesExported(Rule):
    id = "Notion.Many.Pages.Exported-prototype"
    display_name = "Notion Many Pages Exported"
    log_types = [LogType.NOTION_AUDIT_LOGS]
    tags = ["Notion", "Data Security", "Data Exfiltration"]
    default_severity = Severity.HIGH
    default_description = "A Notion User exported multiple pages."
    threshold = 10
    default_runbook = "Possible Data Exfiltration. Follow up with the Notion User to determine if this was done for a valid business reason."
    default_reference = "https://www.notion.so/help/export-your-content"

    def rule(self, event):
        return event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>") == "page.exported"

    def title(self, event):
        user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
        return f"Notion User [{user}] exported multiple pages."

    def alert_context(self, event):
        context = notion_alert_context(event)
        page_id = event.deep_get("event", "details", "target", "page_id", default="<NO_PAGE_ID_FOUND>")
        context["page_id"] = page_id
        return context

    tests = [
        RuleTest(
            name="Other Event",
            expected_result=False,
            log={
                "event": {
                    "id": "...",
                    "timestamp": "2023-06-02T20:16:41.217Z",
                    "workspace_id": "..",
                    "actor": {
                        "id": "..",
                        "object": "user",
                        "type": "person",
                        "person": {"email": "homer.simpson@yourcompany.io"},
                    },
                    "ip_address": "...",
                    "platform": "mac-desktop",
                    "type": "workspace.content_exported",
                    "workspace.content_exported": {},
                },
            },
        ),
        RuleTest(
            name="Many Pages Exported",
            expected_result=True,
            log={
                "event": {
                    "actor": {
                        "id": "bd37477c-869d-418b-abdb-0fc727b38b5e",
                        "object": "user",
                        "person": {"email": "homer.simpson@yourcompany.io"},
                        "type": "person",
                    },
                    "details": {
                        "parent": {"type": "workspace_id", "workspace_id": "ab99as87-6abc-4dcf-808b-111999882299"},
                        "target": {"page_id": "3cd2c560-d1b9-474e-b46e-gh8899002763", "type": "page_id"},
                    },
                    "id": "d4b9963f-12a8-4b01-b597-233a140abf5e",
                    "ip_address": "12.12.12.12",
                    "platform": "web",
                    "timestamp": "2023-06-01 18:57:07.486000000",
                    "type": "page.exported",
                    "workspace_id": "ea65b016-6abc-4dcf-808b-e119617b55d1",
                },
            },
        ),
    ]
