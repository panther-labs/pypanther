from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

netskope_many_deletes_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="True positive",
        ExpectedResult=True,
        Log={
            "_id": "1e589befa3da30132362f32a",
            "_insertion_epoch_timestamp": 1702318213,
            "audit_log_event": "Deleted rbi template",
            "count": 1,
            "is_netskope_personnel": False,
            "organization_unit": "",
            "severity_level": 2,
            "timestamp": "2023-12-11 18:10:13.000000000",
            "type": "admin_audit_logs",
            "ur_normalized": "service-account",
            "user": "service-account",
        },
    ),
    PantherRuleTest(
        Name="True negative",
        ExpectedResult=False,
        Log={
            "_id": "1e589befa3da30132362f32a",
            "_insertion_epoch_timestamp": 1702318213,
            "audit_log_event": "Rest API V2 Call",
            "count": 1,
            "is_netskope_personnel": False,
            "organization_unit": "",
            "severity_level": 2,
            "supporting_data": {
                "data_type": "incidents",
                "data_values": [
                    200,
                    "POST",
                    "/api/v2/incidents/uba/getuci",
                    "trid=ccb898fgrhvdd0v0lebg",
                ],
            },
            "timestamp": "2023-12-11 18:10:13.000000000",
            "type": "admin_audit_logs",
            "ur_normalized": "service-account",
            "user": "service-account",
        },
    ),
]


class NetskopeManyDeletes(PantherRule):
    RuleID = "Netskope.ManyDeletes-prototype"
    DisplayName = "Netskope Many Objects Deleted"
    LogTypes = [LogType.Netskope_Audit]
    Tags = ["Netskope", "Configuration Required", "Data Destruction"]
    Reports = {"MITRE ATT&CK": ["TA0040:T1485"]}
    Severity = PantherSeverity.High
    Description = "A user deleted a large number of objects in a short period of time."
    Threshold = 10
    Runbook = "A user deleted a large number of objects in a short period of time.  Validate that this activity is expected and authorized."
    Reference = "https://docs.netskope.com/en/netskope-help/admin-console/administration/audit-log/"
    Tests = netskope_many_deletes_tests

    def rule(self, event):
        audit_log_event = event.get("audit_log_event")
        if audit_log_event and "Delete" in audit_log_event:
            return True
        return False

    def title(self, event):
        user = event.get("user", "<USER_NOT_FOUND>")
        return f"[{user}] deleted many objects in a short time"
