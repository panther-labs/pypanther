from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class TeleportLockCreated(Rule):
    id = "Teleport.LockCreated-prototype"
    display_name = "A Teleport Lock was created"
    log_types = [LogType.GRAVITATIONAL_TELEPORT_AUDIT]
    tags = ["Teleport"]
    default_severity = Severity.INFO
    default_description = "A Teleport Lock was created"
    default_reference = "https://goteleport.com/docs/management/admin/"
    default_runbook = "A Teleport Lock was created; this is an unusual administrative action. Investigate to understand why a Lock was created.\n"
    summary_attributes = ["event", "code", "time", "identity"]

    def rule(self, event):
        return event.get("event") == "lock.created"

    def title(self, event):
        return f"A Teleport Lock was created by {event.get('updated_by', '<UNKNOWN_UPDATED_BY>')} to Lock out user {event.get('target', {}).get('user', '<UNKNOWN_USER>')} on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"

    tests = [
        RuleTest(
            name="A Lock was created",
            expected_result=True,
            log={
                "cluster_name": "teleport.example.com",
                "code": "TLK00I",
                "ei": 0,
                "event": "lock.created",
                "expires": "0001-01-01T00:00:00Z",
                "name": "88888888-4444-4444-4444-222222222222",
                "target": {"user": "user-to-disable"},
                "time": "2023-09-21T00:00:00.000000Z",
                "uid": "88888888-4444-4444-4444-222222222222",
                "updated_by": "max.mustermann@example.com",
                "user": "max.mustermann@example.com",
            },
        ),
    ]
