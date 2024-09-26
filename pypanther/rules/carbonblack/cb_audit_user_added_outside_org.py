from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class CarbonBlackAuditUserAddedOutsideOrg(Rule):
    id = "CarbonBlack.Audit.User.Added.Outside.Org-prototype"
    log_types = [LogType.CARBON_BLACK_AUDIT]
    default_description = "Detects when a user from a different organization is added to Carbon Black."
    display_name = "Carbon Black User Added Outside Org"
    default_severity = Severity.HIGH
    tags = ["Persistence", "Create Account"]
    reports = {"MITRE ATT&CK": ["TA0003:T1136"]}
    default_reference = "https://docs.vmware.com/en/VMware-Carbon-Black-Cloud/services/carbon-black-cloud-user-guide/GUID-516BAF8C-A13D-4FC7-AA92-923159C13083.html"
    PATTERNS = ("Added user ",)

    def rule(self, event):
        desc = event.get("description", "")
        if not any(desc.startswith(pattern) for pattern in self.PATTERNS):
            return False
        src_user = event.get("loginName", "")
        src_domain = src_user.split("@")[1]
        dst_user = desc.split(" ")[2]
        dst_domain = dst_user.split("@")[1]
        if src_domain != dst_domain:
            return True
        return False

    def title(self, event):
        user = event.get("loginName", "<NO_USERNAME_FOUND>")
        ip_addr = event.get("clientIp", "<NO_IP_FOUND>")
        desc = event.get("description", "<NO_DESCRIPTION_FOUND>")
        return f"{user} [{ip_addr}] {desc}"

    tests = [
        RuleTest(
            name="Outside org",
            expected_result=True,
            log={
                "clientIp": "12.34.56.78",
                "description": "Added user badguy@acme.io to org 12345 (Email Invitation)",
                "eventId": "d109e568832111ee8ab2057b240e65f8",
                "eventTime": "2023-11-14 19:12:55.917000000",
                "flagged": False,
                "loginName": "bob.ross@acme.com",
                "orgName": "acme.com",
                "verbose": False,
            },
        ),
        RuleTest(
            name="Inside org",
            expected_result=False,
            log={
                "clientIp": "12.34.56.78",
                "description": "Added user goodguy@acme.com to org 12345 (Email Invitation)",
                "eventId": "d109e568832111ee8ab2057b240e65f8",
                "eventTime": "2023-11-14 19:12:55.917000000",
                "flagged": False,
                "loginName": "bob.ross@acme.com",
                "orgName": "acme.com",
                "verbose": False,
            },
        ),
    ]
