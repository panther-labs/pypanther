from typing import List

from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_iocs import SUNBURST_FQDN_IOCS, ioc_match, sanitize_domain

i_o_c_sunburst_f_q_d_n_i_o_cs_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Non-matching traffic",
        ExpectedResult=False,
        Log={
            "dstport": 53,
            "dstaddr": "1.1.1.1",
            "srcaddr": "10.0.0.1",
            "p_any_domain_names": ["example.com"],
        },
    ),
    PantherRuleTest(
        Name="Sunburst Indicator of Compromise (FQDN) Detected",
        ExpectedResult=True,
        Log={
            "srcaddr": "13.59.205.66",
            "dstaddr": "10.0.0.1",
            "p_any_domain_names": ["incomeupdate.com"],
        },
    ),
]


class IOCSunburstFQDNIOCs(PantherRule):
    RuleID = "IOC.SunburstFQDNIOCs-prototype"
    DisplayName = "Sunburst Indicators of Compromise (FQDN)"
    Enabled = True
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
    Tags = [
        "AWS",
        "Box",
        "DNS",
        "GCP",
        "GSuite",
        "SSH",
        "OneLogin",
        "Osquery",
        "Initial Access:Trusted Relationship",
        "Deprecated",
    ]
    Reports = {"MITRE ATT&CK": ["TA0001:T1199"]}
    Severity = Severity.High
    Description = "Monitors for communication to known Sunburst Backdoor FQDNs. These IOCs indicate a potential breach and have been associated with a sophisticated nation-state actor.\n"
    Reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html\n"
    Runbook = "Investigate the resources communicating with the matched IOC for signs of compromise or other malicious activity. Consider rotating credentials on any systems observed communicating with these known malicious systems.\n"
    SummaryAttributes = ["p_any_domain_names", "p_any_ip_addresses", "p_any_sha256_hashes"]
    Tests = i_o_c_sunburst_f_q_d_n_i_o_cs_tests

    def rule(self, event):
        return any(ioc_match(event.get("p_any_domain_names"), SUNBURST_FQDN_IOCS))

    def title(self, event):
        domains = ",".join(ioc_match(event.get("p_any_domain_names"), SUNBURST_FQDN_IOCS))
        return sanitize_domain(f"Sunburst Indicator of Compromise Detected [Domains]: {domains}")
