from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.notion import notion_alert_context


@panther_managed
class NotionTeamspaceOwnerAdded(Rule):
    id = "Notion.TeamspaceOwnerAdded-prototype"
    display_name = "Notion Teamspace Owner Added"
    log_types = [LogType.NOTION_AUDIT_LOGS]
    tags = ["Notion", "Privilege Escalation"]
    default_description = "A Notion User was added as a Teamspace owner."
    default_severity = Severity.MEDIUM
    default_runbook = "Possible Privilege Escalation. Follow up with the Notion User to determine if this was done for a valid business reason."

    def rule(self, event):
        added = (
            event.deep_get("event", "type", default="") == "teamspace.permissions.member_added"
            and event.deep_get("event", "details", "role", default="") == "owner"
        )
        updated = (
            event.deep_get("event", "type", default="") == "teamspace.permissions.member_role_updated"
            and event.deep_get("event", "details", "new_role", default="") == "owner"
        )
        return added or updated

    def title(self, event):
        actor = event.deep_get("event", "actor", "person", "email", default="NO_ACTOR_FOUND")
        member = event.deep_get("event", "details", "member", "person", "email", default="NO_MEMBER_FOUND")
        teamspace = event.deep_get("event", "details", "target", "name", default="NO_TEAMSPACE_FOUND")
        return f"[{actor}] added [{member}] as owner of [{teamspace}] Teamspace"

    def alert_context(self, event):
        return notion_alert_context(event)

    tests = [
        RuleTest(
            name="Member Added",
            expected_result=False,
            log={
                "event": {
                    "actor": {
                        "id": "c16137bb-5078-4eac-b026-5cbd2f9a027a",
                        "object": "user",
                        "person": {"email": "bill@example.com"},
                        "type": "person",
                    },
                    "details": {
                        "member": {
                            "id": "c16137bb-5078-4eac-b026-5cbd2f9a027a",
                            "object": "user",
                            "person": {"email": "bob@example.com"},
                            "type": "person",
                        },
                        "role": "member",
                        "target": {
                            "id": "b8db234d-71eb-49e2-a5ed-7935ca764920",
                            "name": "General",
                            "object": "teamspace",
                        },
                    },
                    "id": "eed75a56-ca1b-453b-afd8-73789bc19398",
                    "ip_address": "11.22.33.44",
                    "platform": "web",
                    "timestamp": "2023-12-13 16:20:14.966000000",
                    "type": "teamspace.permissions.member_added",
                    "workspace_id": "ea65b016-6abc-4dcf-808b-e119617b55d1",
                },
            },
        ),
        RuleTest(
            name="Owner Added",
            expected_result=True,
            log={
                "event": {
                    "actor": {
                        "id": "c16137bb-5078-4eac-b026-5cbd2f9a027a",
                        "object": "user",
                        "person": {"email": "malicious.insider@example.com"},
                        "type": "person",
                    },
                    "details": {
                        "member": {
                            "id": "c16137bb-5078-4eac-b026-5cbd2f9a027a",
                            "object": "user",
                            "person": {"email": "bad.dude@example.com"},
                            "type": "person",
                        },
                        "new_role": "owner",
                        "target": {
                            "id": "b8db234d-71eb-49e2-a5ed-7935ca764920",
                            "name": "General",
                            "object": "teamspace",
                        },
                    },
                    "id": "6019b995-0158-4430-8263-89ad7905bd1d",
                    "ip_address": "11.22.33.44",
                    "platform": "web",
                    "timestamp": "2023-12-13 16:38:04.264000000",
                    "type": "teamspace.permissions.member_role_updated",
                    "workspace_id": "ea65b016-6abc-4dcf-808b-e119617b55d1",
                },
            },
        ),
    ]
