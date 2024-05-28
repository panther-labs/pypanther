from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

carbon_black_audit_user_added_outside_org_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Outside org",
        ExpectedResult=True,
        Log={
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
    PantherRuleTest(
        Name="Inside org",
        ExpectedResult=False,
        Log={
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


class CarbonBlackAuditUserAddedOutsideOrg(PantherRule):
    RuleID = "CarbonBlack.Audit.User.Added.Outside.Org-prototype"
    LogTypes = [LogType.CarbonBlack_Audit]
    Description = "Detects when a user from a different organization is added to Carbon Black."
    DisplayName = "Carbon Black User Added Outside Org"
    Severity = PantherSeverity.High
    Tags = ["Persistence", "Create Account"]
    Reports = {"MITRE ATT&CK": ["TA0003:T1136"]}
    Reference = "https://docs.vmware.com/en/VMware-Carbon-Black-Cloud/services/carbon-black-cloud-user-guide/GUID-516BAF8C-A13D-4FC7-AA92-923159C13083.html"
    Tests = carbon_black_audit_user_added_outside_org_tests
    PATTERNS = ("Added user ",)

    def rule(self, event):
        desc = event.get("description", "")
        if not any((desc.startswith(pattern) for pattern in self.PATTERNS)):
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
