from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.notion import notion_alert_context


@panther_managed
class NotionWorkspaceSCIMTokenGenerated(Rule):
    id = "Notion.Workspace.SCIM.Token.Generated-prototype"
    display_name = "Notion SCIM Token Generated"
    log_types = [LogType.NOTION_AUDIT_LOGS]
    tags = ["Notion", "Application Security", "Supply Chain Attack"]
    default_description = "A Notion User generated a SCIM token."
    default_severity = Severity.MEDIUM
    default_runbook = "Possible Initial Access. Follow up with the Notion User to determine if this was done for a valid business reason."
    default_reference = "https://www.notion.so/help/provision-users-and-groups-with-scim"

    def rule(self, event):
        event_type = event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>")
        return event_type == "workspace.scim_token_generated"

    def title(self, event):
        user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
        workspace_id = event.deep_get("event", "workspace_id", default="<NO_WORKSPACE_ID_FOUND>")
        return f"Notion User [{user}] generated a SCIM token for workspace id [{workspace_id}]."

    def alert_context(self, event):
        return notion_alert_context(event)

    tests = [
        RuleTest(
            name="other event",
            expected_result=False,
            log={
                "event": {
                    "id": "...",
                    "timestamp": "2023-06-02T20:16:41.217Z",
                    "workspace_id": "123",
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
            name="Token Generated",
            expected_result=True,
            log={
                "event": {
                    "id": "...",
                    "timestamp": "2023-06-02T20:21:01.873Z",
                    "workspace_id": "123",
                    "actor": {
                        "id": "..",
                        "object": "user",
                        "type": "person",
                        "person": {"email": "homer.simpson@yourcompany.com"},
                    },
                    "ip_address": "...",
                    "platform": "mac-desktop",
                    "type": "workspace.scim_token_generated",
                    "workspace.scim_token_generated": {},
                },
            },
        ),
    ]
