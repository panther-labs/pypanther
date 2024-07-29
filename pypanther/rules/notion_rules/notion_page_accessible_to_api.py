from pypanther import LogType, Rule, Severity, panther_managed
from pypanther.helpers.panther_notion_helpers import notion_alert_context


@panther_managed
class NotionPagePermsAPIPermsChanged(Rule):
    display_name = "Notion Page API Permissions Changed"
    id = "Notion.PagePerms.APIPermsChanged-prototype"
    log_types = [LogType.NOTION_AUDIT_LOGS]
    tags = ["Notion", "Data Security", "Unapproved 3rd Party Apps"]
    default_severity = Severity.LOW
    default_description = "A new API integration was added to a Notion page, or it's permissions were changed."
    default_runbook = "Potential information exposure - review the shared page and rectify if needed."
    default_reference = "https://www.notion.so/help/sharing-and-permissions"
    # These event types correspond to users adding or editing the default role on a public page
    event_types = ("page.permissions.integration_role_added", "page.permissions.integration_role_updated")

    def rule(self, event):
        return event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>") in self.event_types

    def title(self, event):
        user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
        page_id = event.deep_get("event", "details", "target", "page_id", default="<NO_PAGE_ID_FOUND>")
        return f"Notion User [{user}] added an integration to page [{page_id}]."

    def alert_context(self, event):
        context = notion_alert_context(event)
        page_id = event.deep_get("event", "details", "target", "page_id", default="<NO_PAGE_ID_FOUND>")
        context["page_id"] = page_id
        return context
