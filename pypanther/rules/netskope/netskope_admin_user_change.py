from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class NetskopeAdminUserChange(Rule):
    id = "Netskope.AdminUserChange-prototype"
    display_name = "An administrator account was created, deleted, or modified."
    log_types = [LogType.NETSKOPE_AUDIT]
    tags = ["Netskope", "Account Manipulation"]
    reports = {"MITRE ATT&CK": ["TA0004:T1098"]}
    default_severity = Severity.HIGH
    default_reference = (
        "https://docs.netskope.com/en/netskope-help/admin-console/administration/managing-administrators/"
    )
    default_description = "An administrator account was created, deleted, or modified."
    default_runbook = "An administrator account was created, deleted, or modified.  Validate that this activity is expected and authorized."
    ADMIN_USER_CHANGE_EVENTS = [
        "Created new admin",
        "Added SSO Admin",
        "Edited SSO Admin Record",
        "Created new support admin",
        "Edit admin record",
        "Deleted admin",
        "Enabled admin",
        "Disabled admin",
        "Unlocked admin",
        "Updated admin settings",
        "Deleted Netskope SSO admin",
    ]

    def rule(self, event):
        if event.get("audit_log_event") in self.ADMIN_USER_CHANGE_EVENTS:
            return True
        return False

    def title(self, event):
        user = event.get("user", "<USER_NOT_FOUND>")
        audit_log_event = event.get("audit_log_event", "<EVENT_NOT_FOUND>")
        return f"User [{user}] performed [{audit_log_event}]"

    def severity(self, event):
        audit_log_event = event.get("audit_log_event", "no_data").lower()
        if "create" in audit_log_event or "add" in audit_log_event or "delete" in audit_log_event:
            return "CRITICAL"
        return "HIGH"

    tests = [
        RuleTest(
            name="True positive",
            expected_result=True,
            log={
                "_id": "e5ca619b059fccdd0cfd9398",
                "_insertion_epoch_timestamp": 1702308331,
                "audit_log_event": "Created new admin",
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
