from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class NetskopeUnauthorizedAPICalls(Rule):
    id = "Netskope.UnauthorizedAPICalls-prototype"
    display_name = "Netskope Many Unauthorized API Calls"
    log_types = [LogType.NETSKOPE_AUDIT]
    tags = ["Netskope", "Configuration Required", "Brute Force"]
    reports = {"MITRE ATT&CK": ["TA0006:T1110"]}
    default_severity = Severity.HIGH
    default_description = "Many unauthorized API calls were observed for a user in a short period of time."
    threshold = 10
    default_runbook = "An account is making many unauthorized API calls.  This could indicate brute force activity, or expired service account credentials."
    default_reference = (
        "https://docs.netskope.com/en/netskope-help/data-security/netskope-private-access/private-access-rest-apis/"
    )

    def rule(self, event):
        data_values = event.deep_walk("supporting_data", "data_values")
        if data_values and data_values[0] == 403:
            return True
        return False

    def title(self, event):
        user = event.get("user", "<USER_NOT_FOUND>")
        return f"Many unauthorized API calls from user [{user}]"

    tests = [
        RuleTest(
            name="True positive",
            expected_result=True,
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
                    "data_values": [403, "POST", "/api/v2/incidents/uba/getuci", "trid=ccb898fgrhvdd0v0lebg"],
                },
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
