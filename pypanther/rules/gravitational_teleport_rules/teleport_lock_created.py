from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

teleport_lock_created_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="A Lock was created",
        ExpectedResult=True,
        Log={
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
    )
]


class TeleportLockCreated(PantherRule):
    RuleID = "Teleport.LockCreated-prototype"
    DisplayName = "A Teleport Lock was created"
    LogTypes = [LogType.Gravitational_TeleportAudit]
    Tags = ["Teleport"]
    Severity = PantherSeverity.Info
    Description = "A Teleport Lock was created"
    Reference = "https://goteleport.com/docs/management/admin/"
    Runbook = "A Teleport Lock was created; this is an unusual administrative action. Investigate to understand why a Lock was created.\n"
    SummaryAttributes = ["event", "code", "time", "identity"]
    Tests = teleport_lock_created_tests

    def rule(self, event):
        return event.get("event") == "lock.created"

    def title(self, event):
        return f"A Teleport Lock was created by {event.get('updated_by', '<UNKNOWN_UPDATED_BY>')} to Lock out user {event.get('target', {}).get('user', '<UNKNOWN_USER>')} on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
