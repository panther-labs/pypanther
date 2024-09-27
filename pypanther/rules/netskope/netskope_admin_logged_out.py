from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class NetskopeAdminLoggedOutLoginFailures(Rule):
    id = "Netskope.AdminLoggedOutLoginFailures-prototype"
    display_name = "Admin logged out because of successive login failures"
    log_types = [LogType.NETSKOPE_AUDIT]
    tags = ["Netskope", "Brute Force"]
    reports = {"MITRE ATT&CK": ["TA0006:T1110"]}
    default_severity = Severity.MEDIUM
    default_description = "An admin was logged out because of successive login failures."
    default_runbook = "An admin was logged out because of successive login failures.  This could indicate brute force activity against this account."
    default_reference = "https://docs.netskope.com/en/netskope-help/admin-console/administration/audit-log/"

    def rule(self, event):
        if event.get("audit_log_event") == "Admin logged out because of successive login failures":
            return True
        return False

    def title(self, event):
        user = event.get("user", "<USER_NOT_FOUND>")
        return f"Admin [{user}] was logged out because of successive login failures"

    tests = [
        RuleTest(
            name="True positive",
            expected_result=True,
            log={
                "_id": "e5ca619b059fccdd0cfd9398",
                "_insertion_epoch_timestamp": 1702308331,
                "audit_log_event": "Admin logged out because of successive login failures",
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
