from typing import List

from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_iocs import SUNBURST_IP_IOCS, ioc_match

ioc_sunburst_ipio_cs_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Non-matching traffic",
        ExpectedResult=False,
        Log={"dstport": 53, "dstaddr": "1.1.1.1", "srcaddr": "10.0.0.1"},
    ),
    PantherRuleTest(
        Name="Sunburst Indicator of Compromise (IP) Detected",
        ExpectedResult=True,
        Log={"srcaddr": "0.0.0.1", "dstaddr": "10.0.0.1", "p_any_ip_addresses": ["0.0.0.1"]},
    ),
]


class IOCSunburstIPIOCs(PantherRule):
    RuleID = "IOC.SunburstIPIOCs-prototype"
    DisplayName = "--Deprecated-- Sunburst Indicators of Compromise (IP)"
    Enabled = False
    LogTypes = [
        "AWS.ALB",
        "AWS.CloudTrail",
        "AWS.GuardDuty",
        "AWS.S3ServerAccess",
        "AWS.VPCFlow",
        "Box.Event",
        "CiscoUmbrella.DNS",
        "GCP.AuditLog",
        "Gravitational.TeleportAudit",
        "GSuite.Reports",
        "Okta.SystemLog",
        "OneLogin.Events",
        "Osquery.Differential",
    ]
    Tags = ["AWS", "Box", "DNS", "GCP", "GSuite", "SSH", "OneLogin", "Osquery", "Deprecated"]
    Severity = Severity.High
    Description = "Monitors for communication to known Sunburst Backdoor IPs. These IOCs indicate a potential breach and have been associated with a sophisticated nation-state actor.\n"
    Reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html\n"
    Runbook = "Investigate the resources communicating with the matched IOC for signs of compromise or other malicious activity. Consider rotating credentials on any systems observed communicating with these known malicious systems.\n"
    SummaryAttributes = ["p_any_domain_names", "p_any_ip_addresses", "p_any_sha256_hashes"]
    Tests = ioc_sunburst_ipio_cs_tests

    def rule(self, event):
        return any(ioc_match(event.get("p_any_ip_addresses"), SUNBURST_IP_IOCS))

    def title(self, event):
        ips = ",".join(ioc_match(event.get("p_any_ip_addresses"), SUNBURST_IP_IOCS))
        return f"Sunburst Indicator of Compromise Detected [IPs]: {ips}"
