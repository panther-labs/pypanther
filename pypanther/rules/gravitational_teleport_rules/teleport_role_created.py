from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

teleport_role_created_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="A role was created",
        ExpectedResult=True,
        Log={
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
    )
]


class TeleportRoleCreated(PantherRule):
    RuleID = "Teleport.RoleCreated-prototype"
    DisplayName = "A Teleport Role was modified or created"
    LogTypes = [LogType.Gravitational_TeleportAudit]
    Tags = ["Teleport"]
    Severity = PantherSeverity.Medium
    Description = "A Teleport Role was modified or created"
    Reports = {"MITRE ATT&CK": ["TA0003:T1098.001"]}
    Reference = "https://goteleport.com/docs/management/admin/"
    Runbook = "A Teleport Role was modified or created. Validate its legitimacy.\n"
    SummaryAttributes = ["event", "code", "user", "name"]
    Tests = teleport_role_created_tests

    def rule(self, event):
        return event.get("event") == "role.created"

    def title(self, event):
        return f"User [{event.get('user', '<UNKNOWN_USER>')}] created Role [{event.get('name', '<UNKNOWN_NAME>')}] on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
