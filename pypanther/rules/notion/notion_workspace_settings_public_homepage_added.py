from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_notion_helpers import notion_alert_context

notion_workspace_public_page_added_tests: list[RuleTest] = [
    RuleTest(
        name="Public page added",
        expected_result=True,
        log={
            "event": {
                "id": "eeeeeeee-dddd-4444-bbbb-4444444444444",
                "timestamp": "2023-05-15T19:14:21.031Z",
                "workspace_id": "vvvvvvvv-dddd-4444-bbbb-666666666666",
                "actor": {
                    "object": "user",
                    "id": "44444444-cccc-7777-aaaa-666666666666",
                    "type": "person",
                    "person": {"email": "example@personemail.com"},
                },
                "ip_address": "00.000.00.000",
                "platform": "web",
                "type": "workspace.settings.public_homepage_added",
                "workspace.settings.public_homepage_added": {
                    "new_public_page": {"type": "database_id", "database_id": "4b801dc7-d724-4fbb-afd0-9885cbc12405"},
                },
            },
        },
    ),
    RuleTest(
        name="Workspace Exported",
        expected_result=False,
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


@panther_managed
class NotionWorkspacePublicPageAdded(Rule):
    id = "Notion.Workspace.Public.Page.Added-prototype"
    display_name = "Notion Workspace public page added"
    log_types = [LogType.NOTION_AUDIT_LOGS]
    tags = ["Notion", "Data Security", "Information Disclosure"]
    default_severity = Severity.INFO
    default_description = "A Notion page was set to public in your worksace."
    default_runbook = "A Notion page was made public. Check with the author to determine why this page was made public."
    default_reference = "https://www.notion.so/help/public-pages-and-web-publishing"
    tests = notion_workspace_public_page_added_tests

    def rule(self, event):
        event_type = event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>")
        return event_type == "workspace.settings.public_homepage_added"

    def title(self, event):
        actor = event.deep_get("event", "actor", "person", "email", default="<NO_EMAIL_FOUND>")
        wkspc_id = event.deep_get("event", "workspace_id", default="<NO_WORKSPACE_ID_FOUND>")
        db_id = deep_get(
            event,
            "event",
            "workspace.settings.public_homepage_added",
            "new_public_page",
            "database_id",
            default="<NO_DATABASE_ID_FOUND>",
        )
        return f"Notion User [{actor}] added a new public homepage [{db_id}] in workspace [{wkspc_id}]"

    def alert_context(self, event):
        context = notion_alert_context(event)
        workspace_id = event.deep_get("event", "workspace_id", default="<NO_WORKSPACE_ID_FOUND>")
        db_id = deep_get(
            event,
            "event",
            "workspace.settings.public_homepage_added",
            "new_public_page",
            "database_id",
            default="<NO_DATABASE_ID_FOUND>",
        )
        context["workspace_id"] = workspace_id
        context["page_id"] = db_id
        return context
