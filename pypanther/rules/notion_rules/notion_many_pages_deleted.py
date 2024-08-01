from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_notion_helpers import notion_alert_context

notion_many_pages_deleted_tests: list[RuleTest] = [
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
        name="Many Pages Deleted",
        expected_result=True,
        log={
            "event": {
                "actor": {
                    "id": "af06b6ff-dd5e-4024-b9ef-78fe77f55884",
                    "object": "user",
                    "person": {"email": "homer.simpson@yourcompany.io"},
                    "type": "person",
                },
                "details": {
                    "parent": {"database_id": "543af759-3010-4355-a71e-4sdfs3566a", "type": "database_id"},
                    "target": {"page_id": "93cf05d3-6805-4ddc-abba-adsfjhnlkwje785", "type": "page_id"},
                },
                "id": "768873bf-6b2c-40e8-b27c-1c199c4d6ae7",
                "ip_address": "12.12.12.12",
                "platform": "web",
                "timestamp": "2023-05-24 20:17:41.905000000",
                "type": "page.deleted",
                "workspace_id": "ea65b016-6abc-4dcf-808b-sdfg445654",
            },
        },
    ),
]


@panther_managed
class NotionManyPagesDeleted(Rule):
    id = "Notion.Many.Pages.Deleted-prototype"
    display_name = "Notion Many Pages Deleted"
    log_types = [LogType.NOTION_AUDIT_LOGS]
    tags = ["Notion", "Data Security", "Data Destruction"]
    default_severity = Severity.MEDIUM
    default_description = "A Notion User deleted multiple pages."
    threshold = 10
    default_runbook = "Possible Data Destruction. Follow up with the Notion User to determine if this was done for a valid business reason."
    default_reference = "https://www.notion.so/help/duplicate-delete-and-restore-content"
    tests = notion_many_pages_deleted_tests

    def rule(self, event):
        return event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>") == "page.deleted"

    def title(self, event):
        user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
        return f"Notion User [{user}] deleted multiple pages."

    def alert_context(self, event):
        context = notion_alert_context(event)
        page_id = event.deep_get("event", "details", "target", "page_id", default="<NO_PAGE_ID_FOUND>")
        context["page_id"] = page_id
        return context
