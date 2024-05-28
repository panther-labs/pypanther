from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_notion_helpers import notion_alert_context
from pypanther.log_types import LogType


class NotionPageSharedToWeb(PantherRule):
    RuleID = "Notion.PageSharedToWeb-prototype"
    DisplayName = "Notion Page Published to Web"
    LogTypes = [LogType.Notion_AuditLogs]
    Tags = ["Notion", "Data Security", "Information Disclosure"]
    Severity = PantherSeverity.Low
    Description = "A Notion User published a page to the web."
    Runbook = "Potential information exposure - review the shared page and rectify if needed."
    Reference = "https://www.notion.so/help/public-pages-and-web-publishing"
    # These event types correspond to users adding or editing the default role on a public page
    event_types = (
        "page.permissions.shared_to_public_role_added",
        "page.permissions.shared_to_public_role_updated",
    )

    def rule(self, event):
        return event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>") in self.event_types

    def title(self, event):
        user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
        page_name = event.deep_get("event", "details", "page_name", default="<NO_PAGE_NAME_FOUND>")
        return f"Notion User [{user}] changed the status of page [{page_name}] to public."

    def alert_context(self, event):
        context = notion_alert_context(event)
        page_name = event.deep_get("event", "details", "page_name", default="<NO_PAGE_NAME_FOUND>")
        context["page_name"] = page_name
        return context
