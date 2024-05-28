from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

netskope_admin_logged_out_login_failures_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="True positive",
        ExpectedResult=True,
        Log={
            "_id": "e5ca619b059fccdd0cfd9398",
            "_insertion_epoch_timestamp": 1702308331,
            "audit_log_event": "Admin logged out because of successive login failures",
            "count": 1,
            "is_netskope_personnel": True,
            "organization_unit": "",
            "severity_level": 2,
            "supporting_data": {
                "data_type": "user",
                "data_values": ["11.22.33.44", "adminsupport@netskope.com"],
            },
            "timestamp": "2023-12-11 15:25:31.000000000",
            "type": "admin_audit_logs",
            "ur_normalized": "adminsupport@netskope.com",
            "user": "adminsupport@netskope.com",
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


class NetskopeAdminLoggedOutLoginFailures(PantherRule):
    RuleID = "Netskope.AdminLoggedOutLoginFailures-prototype"
    DisplayName = "Admin logged out because of successive login failures"
    LogTypes = [LogType.Netskope_Audit]
    Tags = ["Netskope", "Brute Force"]
    Reports = {"MITRE ATT&CK": ["TA0006:T1110"]}
    Severity = PantherSeverity.Medium
    Description = "An admin was logged out because of successive login failures."
    Runbook = "An admin was logged out because of successive login failures.  This could indicate brute force activity against this account."
    Reference = "https://docs.netskope.com/en/netskope-help/admin-console/administration/audit-log/"
    Tests = netskope_admin_logged_out_login_failures_tests

    def rule(self, event):
        if event.get("audit_log_event") == "Admin logged out because of successive login failures":
            return True
        return False

    def title(self, event):
        user = event.get("user", "<USER_NOT_FOUND>")
        return f"Admin [{user}] was logged out because of successive login failures"
