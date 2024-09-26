from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class CarbonBlackAuditAdminGrant(Rule):
    id = "CarbonBlack.Audit.Admin.Grant-prototype"
    log_types = [LogType.CARBON_BLACK_AUDIT]
    default_description = "Detects when a user is granted Admin or Super Admin permissions."
    display_name = "Carbon Black Admin Role Granted"
    default_severity = Severity.HIGH
    tags = ["Privilege Escalation", "Account Manipulation"]
    reports = {"MITRE ATT&CK": ["TA0004:T1098"]}
    default_reference = "https://docs.vmware.com/en/VMware-Carbon-Black-Cloud/services/carbon-black-cloud-user-guide/GUID-CF5ACD2C-A534-46C8-AE06-E1884DB37B58.html"
    PREFIXES = ("Updated grant: ", "Created grant: ")

    def rule(self, event):
        desc = event.get("description", "")
        return all(
            [
                event.get("requestUrl", "").startswith("/access/"),
                any(desc.startswith(prefix) for prefix in self.PREFIXES),
                "Admin" in desc,
            ],
        )

    def title(self, event):
        user = event.get("loginName", "<NO_USERNAME_FOUND>")
        ip_addr = event.get("clientIp", "<NO_IP_FOUND>")
        desc = event.get("description", "<NO_DESCRIPTION_FOUND>")
        return f"{user} [{ip_addr}] {desc}"

    def severity(self, event):
        if "Super Admin" in event.get("description", ""):
            return "CRITICAL"
        return "HIGH"

    tests = [
        RuleTest(
            name="Super Admin granted",
            expected_result=True,
            log={
                "clientIp": "12.34.56.78",
                "description": "Created grant: psc:cnn:A1234567:BC1234567890 with role Super Admin",
                "eventId": "66443924833011eeac3cb393f3d07f9f",
                "eventTime": "2023-11-14 20:57:19.186000000",
                "flagged": False,
                "loginName": "bob.ross@acme.com",
                "orgName": "acme.com",
                "requestUrl": "/access/v2/orgs/A1234567/grants",
                "verbose": False,
            },
        ),
        RuleTest(
            name="Admin granted",
            expected_result=True,
            log={
                "clientIp": "12.34.56.78",
                "description": "Created grant: psc:cnn:A1234567:BC1234567890 with role Administrator",
                "eventId": "66443924833011eeac3cb393f3d07f9f",
                "eventTime": "2023-11-14 20:57:19.186000000",
                "flagged": False,
                "loginName": "bob.ross@acme.com",
                "orgName": "acme.com",
                "requestUrl": "/access/v2/orgs/A1234567/grants",
                "verbose": False,
            },
        ),
        RuleTest(
            name="Other role granted",
            expected_result=False,
            log={
                "clientIp": "12.34.56.78",
                "description": "Created grant: psc:cnn:A1234567:BC1234567890 with role Read Only",
                "eventId": "66443924833011eeac3cb393f3d07f9f",
                "eventTime": "2023-11-14 20:57:19.186000000",
                "flagged": False,
                "loginName": "bob.ross@acme.com",
                "orgName": "acme.com",
                "requestUrl": "/access/v2/orgs/A1234567/grants",
                "verbose": False,
            },
        ),
    ]
