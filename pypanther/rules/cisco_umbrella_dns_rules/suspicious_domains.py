from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

cisco_umbrella_dns_suspicious_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Suspicious Domain",
        ExpectedResult=True,
        Log={
            "action": "Allow",
            "internalIp": "136.24.229.58",
            "externalIp": "136.24.229.58",
            "timestamp": "2020-05-21 19:20:25.000",
            "responseCode": "NOERROR",
            "domain": "cron.photoscape.ch.",
        },
    ),
    PantherRuleTest(
        Name="Safe Domain",
        ExpectedResult=False,
        Log={
            "action": "Allowed",
            "internalIp": "136.24.229.58",
            "externalIp": "136.24.229.58",
            "timestamp": "2020-05-21 19:20:25.000",
            "responseCode": "NOERROR",
            "domain": "google.com.",
        },
    ),
]


class CiscoUmbrellaDNSSuspicious(PantherRule):
    RuleID = "CiscoUmbrella.DNS.Suspicious-prototype"
    DisplayName = "Cisco Umbrella Suspicious Domains"
    Enabled = False
    DedupPeriodMinutes = 480
    LogTypes = [LogType.CiscoUmbrella_DNS]
    Tags = ["DNS", "Configuration Required"]
    Reference = "https://umbrella.cisco.com/blog/abcs-of-dns"
    Severity = PantherSeverity.Low
    Description = "Monitor suspicious or known malicious domains"
    Runbook = "Inspect the domain and check the host for other indicators of compromise"
    SummaryAttributes = ["action", "internalIp", "externalIp", "domain", "responseCode"]
    Tests = cisco_umbrella_dns_suspicious_tests
    DOMAINS_TO_MONITOR = {"photoscape.ch"}  # Sample malware domain

    def rule(self, event):
        return any((domain in event.get("domain") for domain in self.DOMAINS_TO_MONITOR))

    def title(self, event):
        return "Suspicious lookup to domain " + event.get("domain", "<UNKNOWN_DOMAIN>")
