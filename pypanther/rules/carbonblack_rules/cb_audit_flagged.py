from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

carbon_black_audit_flagged_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Flagged",
        ExpectedResult=True,
        Log={
            "clientIp": "12.34.56.78",
            "description": "User bob.ross@acme.com retrieved secret for API ID JFDNIPS464 in org 12345",
            "eventId": "66443924833011eeac3cb393f3d07f9f",
            "eventTime": "2023-11-14 20:57:19.186000000",
            "flagged": True,
            "loginName": "bob.ross@acme.com",
            "orgName": "acme.com",
            "verbose": False,
        },
    ),
    PantherRuleTest(
        Name="Other role granted",
        ExpectedResult=False,
        Log={
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


class CarbonBlackAuditFlagged(PantherRule):
    RuleID = "CarbonBlack.Audit.Flagged-prototype"
    LogTypes = [LogType.CarbonBlack_Audit]
    Description = "Detects when Carbon Black has flagged a log as important, such as failed login attempts and locked accounts."
    DisplayName = "Carbon Black Log Entry Flagged"
    Severity = PantherSeverity.High
    Tags = ["Credential Access", "Brute Force"]
    Reports = {"MITRE ATT&CK": ["TA0006:T1110"]}
    Reference = "https://docs.vmware.com/en/VMware-Carbon-Black-Cloud/services/carbon-black-cloud-user-guide/GUID-FB61E4E3-6431-4226-A4E3-5949FB75922B.html"
    Tests = carbon_black_audit_flagged_tests

    def rule(self, event):
        return event.get("flagged", False)

    def title(self, event):
        user = event.get("loginName", "<NO_USERNAME_FOUND>")
        ip_addr = event.get("clientIp", "<NO_IP_FOUND>")
        desc = event.get("description", "<NO_DESCRIPTION_FOUND>")
        return f"{user} [{ip_addr}] {desc}"
