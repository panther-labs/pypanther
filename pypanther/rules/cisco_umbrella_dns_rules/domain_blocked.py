from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

cisco_umbrella_dns_blocked_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Domain Blocked",
        ExpectedResult=True,
        Log={
            "action": "Blocked",
            "internalIp": "136.24.229.58",
            "externalIp": "136.24.229.58",
            "timestamp": "2020-05-21 19:20:25.000",
            "responseCode": "NOERROR",
            "domain": "malware.gvt2.com.",
        },
    ),
    PantherRuleTest(
        Name="Action Allowed",
        ExpectedResult=False,
        Log={
            "action": "Allowed",
            "internalIp": "136.24.229.58",
            "externalIp": "136.24.229.58",
            "timestamp": "2020-05-21 19:20:25.000",
            "responseCode": "NOERROR",
            "domain": "beacons3.gvt2.com.",
        },
    ),
]


class CiscoUmbrellaDNSBlocked(PantherRule):
    RuleID = "CiscoUmbrella.DNS.Blocked-prototype"
    DisplayName = "Cisco Umbrella Domain Blocked"
    DedupPeriodMinutes = 480
    LogTypes = [LogType.CiscoUmbrella_DNS]
    Tags = ["DNS"]
    Severity = PantherSeverity.Low
    Description = "Monitor blocked domains"
    Runbook = "Inspect the blocked domain and lookup for malware"
    Reference = "https://support.umbrella.com/hc/en-us/articles/230563627-How-to-determine-if-a-domain-or-resource-is-being-blocked-using-Chrome-Net-Internals"
    SummaryAttributes = ["action", "internalIp", "externalIp", "domain", "responseCode"]
    Tests = cisco_umbrella_dns_blocked_tests

    def rule(self, event):
        return event.get("action") == "Blocked"

    def title(self, event):
        return "Access denied to domain " + event.get("domain", "<UNKNOWN_DOMAIN>")
