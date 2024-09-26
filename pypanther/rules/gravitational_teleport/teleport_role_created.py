from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class TeleportRoleCreated(Rule):
    id = "Teleport.RoleCreated-prototype"
    display_name = "A Teleport Role was modified or created"
    log_types = [LogType.GRAVITATIONAL_TELEPORT_AUDIT]
    tags = ["Teleport"]
    default_severity = Severity.MEDIUM
    default_description = "A Teleport Role was modified or created"
    reports = {"MITRE ATT&CK": ["TA0003:T1098.001"]}
    default_reference = "https://goteleport.com/docs/management/admin/"
    default_runbook = "A Teleport Role was modified or created. Validate its legitimacy.\n"
    summary_attributes = ["event", "code", "user", "name"]

    def rule(self, event):
        return event.get("event") == "role.created"

    def title(self, event):
        return f"User [{event.get('user', '<UNKNOWN_USER>')}] created Role [{event.get('name', '<UNKNOWN_NAME>')}] on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"

    tests = [
        RuleTest(
            name="A role was created",
            expected_result=True,
            log={
                "cluster_name": "teleport.example.com",
                "code": "T9000I",
                "ei": 0,
                "event": "role.created",
                "expires": "0001-01-01T00:00:00Z",
                "name": "teleport-event-handler",
                "time": "2023-09-20T23:00:000.000000Z",
                "uid": "88888888-4444-4444-4444-222222222222",
                "user": "max.mustermann@example.com",
            },
        ),
    ]
