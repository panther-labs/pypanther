from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.base import deep_get
from pypanther.helpers.notion import notion_alert_context


@panther_managed
class NotionPagePermsGuestPermsChanged(Rule):
    id = "Notion.PagePerms.GuestPermsChanged-prototype"
    display_name = "Notion Page Guest Permissions Changed"
    log_types = [LogType.NOTION_AUDIT_LOGS]
    tags = ["Notion", "Data Security", "Information Disclosure"]
    default_severity = Severity.LOW
    default_description = "The external guest permissions for a Notion page have been altered."
    default_runbook = "Potential information exposure - review the shared page and rectify if needed."
    default_reference = "https://www.notion.so/help/sharing-and-permissions"
    # These event types correspond to users adding or editing the default role on a public page
    event_types = ("page.permissions.guest_role_added", "page.permissions.guest_role_updated")

    def rule(self, event):
        return event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>") in self.event_types

    def title(self, event):
        user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
        guest = event.deep_get("event", "details", "entity", "person", "email", default="<NO_USER_FOUND>")
        page_id = event.deep_get("event", "details", "target", "page_id", default="<NO_PAGE_ID_FOUND>")
        event_type = event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>")
        action = {
            "page.permissions.guest_role_added": "added a guest",
            "page.permissions.guest_role_updated": "changed the guest permissions of",
        }.get(event_type, "changed the guest permissions of")
        return f"Notion User [{user}] {action} [{guest}] on page [{page_id}]."

    def alert_context(self, event):
        context = notion_alert_context(event)
        page_id = event.deep_get("event", "details", "target", "page_id", default="<NO_PAGE_ID_FOUND>")
        context["page_id"] = page_id
        details = event.deep_get("event", "details", default={})
        context["guest"] = deep_get(details, "entity", "person", "email", default="<NO_USER_FOUND>")
        context["new_permission"] = deep_get(details, "new_permission", default="<UNKNOWN PERMISSION>")
        context["old_permission"] = deep_get(details, "old_permission", default="<UNKNOWN PERMISSION>")
        return context

    tests = [
        RuleTest(
            name="Guest Role Added",
            expected_result=True,
            log={
                "event": {
                    "actor": {
                        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                        "object": "user",
                        "person": {"email": "aragorn.elessar@lotr.com"},
                        "type": "person",
                    },
                    "details": {
                        "entity": {
                            "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                            "object": "user",
                            "person": {"email": "frodo.baggins@lotr.com"},
                            "type": "person",
                        },
                        "new_permission": "full_access",
                        "old_permission": "none",
                        "page_audience": "shared_internally",
                        "target": {"page_id": "441356b5-557b-4053-8d2f-7932d2607d66", "type": "page_id"},
                    },
                    "id": "e18690f8-e24b-4b03-ba6f-123eb7ec0f08",
                    "timestamp": "2023-08-11 23:02:53.113000000",
                    "type": "page.permissions.guest_role_added",
                    "workspace_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                },
            },
        ),
        RuleTest(
            name="Guest Role Changed",
            expected_result=True,
            log={
                "event": {
                    "actor": {
                        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                        "object": "user",
                        "person": {"email": "aragorn.elessar@lotr.com"},
                        "type": "person",
                    },
                    "details": {
                        "entity": {
                            "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                            "object": "user",
                            "person": {"email": "frodo.baggins@lotr.com"},
                            "type": "person",
                        },
                        "new_permission": "full_access",
                        "old_permission": "read_only",
                        "page_audience": "shared_internally",
                        "target": {"page_id": "441356b5-557b-4053-8d2f-7932d2607d66", "type": "page_id"},
                    },
                    "id": "e18690f8-e24b-4b03-ba6f-123eb7ec0f08",
                    "timestamp": "2023-08-11 23:02:53.113000000",
                    "type": "page.permissions.guest_role_updated",
                    "workspace_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                },
            },
        ),
    ]
