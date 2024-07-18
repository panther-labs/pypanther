from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

netskope_netskope_personnel_activity_tests: list[RuleTest] = [
    RuleTest(
        name="True positive",
        expected_result=True,
        log={
            "_id": "e5ca619b059fccdd0cfd9398",
            "_insertion_epoch_timestamp": 1702308331,
            "audit_log_event": "Login Successful",
            "count": 1,
            "is_netskope_personnel": True,
            "organization_unit": "",
            "severity_level": 2,
            "supporting_data": {"data_type": "user", "data_values": ["11.22.33.44", "adminsupport@netskope.com"]},
            "timestamp": "2023-12-11 15:25:31.000000000",
            "type": "admin_audit_logs",
            "ur_normalized": "adminsupport@netskope.com",
            "user": "adminsupport@netskope.com",
        },
    ),
    RuleTest(
        name="True negative",
        expected_result=False,
        log={
            "_id": "1e589befa3da30132362f32a",
            "_insertion_epoch_timestamp": 1702318213,
            "audit_log_event": "Rest API V2 Call",
            "count": 1,
            "is_netskope_personnel": False,
            "organization_unit": "",
            "severity_level": 2,
            "supporting_data": {
                "data_type": "incidents",
                "data_values": [200, "POST", "/api/v2/incidents/uba/getuci", "trid=ccb898fgrhvdd0v0lebg"],
            },
            "timestamp": "2023-12-11 18:10:13.000000000",
            "type": "admin_audit_logs",
            "ur_normalized": "service-account",
            "user": "service-account",
        },
    ),
]


@panther_managed
class NetskopeNetskopePersonnelActivity(Rule):
    id = "Netskope.NetskopePersonnelActivity-prototype"
    display_name = "Action Performed by Netskope Personnel"
    log_types = [LogType.NETSKOPE_AUDIT]
    tags = ["Netskope", "Supply Chain Compromise"]
    reports = {"MITRE ATT&CK": ["TA0001:T1195"]}
    default_severity = Severity.MEDIUM
    default_description = "An action was performed by Netskope personnel."
    default_runbook = "Action taken by Netskope Personnel.  Validate that this action was authorized."
    default_reference = "https://docs.netskope.com/en/netskope-help/admin-console/administration/audit-log/#filters-1"
    tests = netskope_netskope_personnel_activity_tests

    def rule(self, event):
        if event.get("is_netskope_personnel") is True:
            return True
        return False

    def title(self, event):
        user = event.get("user", "<USER_NOT_FOUND>")
        audit_log_event = event.get("audit_log_event", "<EVENT_NOT_FOUND>")
        return f"Action [{audit_log_event}] performed by Netskope personnel [{user}]"
