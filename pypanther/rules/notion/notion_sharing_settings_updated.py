from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.notion import notion_alert_context


@panther_managed
class NotionSharingSettingsUpdated(Rule):
    id = "Notion.SharingSettingsUpdated-prototype"
    display_name = "Notion Sharing Settings Updated"
    log_types = [LogType.NOTION_AUDIT_LOGS]
    tags = ["Notion", "Data Exfiltration"]
    default_description = "A Notion User enabled sharing for a Workspace or Teamspace."
    default_severity = Severity.MEDIUM
    default_runbook = "Possible Data Exfiltration. Follow up with the Notion User to determine if this was done for a valid business reason."
    EVENTS = (
        "teamspace.settings.allow_public_page_sharing_setting_updated",
        "teamspace.settings.allow_guests_setting_updated",
        "teamspace.settings.allow_content_export_setting_updated",
        "workspace.settings.allow_public_page_sharing_setting_updated",
        "workspace.settings.allow_guests_setting_updated",
        "workspace.settings.allow_content_export_setting_updated",
    )

    def rule(self, event):
        return all(
            [
                event.deep_get("event", "type", default="") in self.EVENTS,
                event.deep_get("event", "details", "state", default="") == "enabled",
            ],
        )

    def title(self, event):
        actor = event.deep_get("event", "actor", "person", "email", default="NO_ACTOR_FOUND")
        action = event.deep_get("event", "type", default="NO.EVENT.FOUND").split(".")[2]
        teamspace = event.deep_get("event", "details", "target", "name", default=None)
        if teamspace:
            return f"[{actor}] enabled [{action}] for [{teamspace}] Teamspace"
        return f"[{actor}] enabled [{action}] for Workspace"

    def alert_context(self, event):
        return notion_alert_context(event)

    tests = [
        RuleTest(
            name="Sharing Enabled",
            expected_result=True,
            log={
                "event": {
                    "actor": {
                        "id": "c16137bb-5078-4eac-b026-5cbd2f9a027a",
                        "object": "user",
                        "person": {"email": "aaron@example.com"},
                        "type": "person",
                    },
                    "details": {"state": "enabled"},
                    "id": "91b29a4b-4978-40e1-ab56-40221f801ce5",
                    "ip_address": "11.22.33.44",
                    "platform": "web",
                    "timestamp": "2023-12-13 16:39:06.860000000",
                    "type": "workspace.settings.allow_guests_setting_updated",
                    "workspace_id": "ea65b016-6abc-4dcf-808b-e119617b55d1",
                },
            },
        ),
        RuleTest(
            name="Sharing Disabled",
            expected_result=False,
            log={
                "event": {
                    "actor": {
                        "id": "c16137bb-5078-4eac-b026-5cbd2f9a027a",
                        "object": "user",
                        "person": {"email": "aaron@example.com"},
                        "type": "person",
                    },
                    "details": {
                        "state": "disabled",
                        "target": {"id": "a70a4074-5cac-4fc5-8e59-109df81e5a93", "name": "R&D", "object": "teamspace"},
                    },
                    "id": "91b29a4b-4978-40e1-ab56-40221f801ce5",
                    "ip_address": "11.22.33.44",
                    "platform": "web",
                    "timestamp": "2023-12-13 16:39:06.860000000",
                    "type": "teamspace.settings.allow_guests_setting_updated",
                    "workspace_id": "ea65b016-6abc-4dcf-808b-e119617b55d1",
                },
            },
        ),
    ]
