from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

netskope_many_deletes_tests: list[RuleTest] = [
    RuleTest(
        name="True positive",
        expected_result=True,
        log={
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
class NetskopeManyDeletes(Rule):
    id = "Netskope.ManyDeletes-prototype"
    display_name = "Netskope Many Objects Deleted"
    log_types = [LogType.NETSKOPE_AUDIT]
    tags = ["Netskope", "Configuration Required", "Data Destruction"]
    reports = {"MITRE ATT&CK": ["TA0040:T1485"]}
    default_severity = Severity.HIGH
    default_description = "A user deleted a large number of objects in a short period of time."
    threshold = 10
    default_runbook = "A user deleted a large number of objects in a short period of time.  Validate that this activity is expected and authorized."
    default_reference = "https://docs.netskope.com/en/netskope-help/admin-console/administration/audit-log/"
    tests = netskope_many_deletes_tests

    def rule(self, event):
        audit_log_event = event.get("audit_log_event")
        if audit_log_event and "Delete" in audit_log_event:
            return True
        return False

    def title(self, event):
        user = event.get("user", "<USER_NOT_FOUND>")
        return f"[{user}] deleted many objects in a short time"
