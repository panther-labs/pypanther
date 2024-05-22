from typing import List
from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_iocs import SUNBURST_SHA256_IOCS, ioc_match

i_o_c_sunburst_s_h_a256_i_o_cs_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Non-matching traffic",
        ExpectedResult=False,
        Log={
            "dstport": 53,
            "dstaddr": "1.1.1.1",
            "srcaddr": "10.0.0.1",
            "p_any_sha256_hashes": [
                "98ea6e4f216f2fb4b69fff9b3a44842c38686ca685f3f55dc48c5d3fb1107be4"
            ],
        },
    ),
    PantherRuleTest(
        Name="Sunburst Indicator of Compromise (SHA-256) Detected",
        ExpectedResult=True,
        Log={
            "srcaddr": "13.59.205.66",
            "dstaddr": "10.0.0.1",
            "p_any_sha256_hashes": [
                "019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134"
            ],
        },
    ),
]


class IOCSunburstSHA256IOCs(PantherRule):
    RuleID = "IOC.SunburstSHA256IOCs-prototype"
    DisplayName = "Sunburst Indicators of Compromise (SHA-256)"
    Enabled = True
    LogTypes = [
        "AWS.ALB",
        "AWS.CloudTrail",
        "AWS.GuardDuty",
        "AWS.S3ServerAccess",
        "Box.Event",
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
    Description = "Monitors for hashes to known Sunburst Backdoor SHA256. These IOCs indicate a potential breach and have been associated with a sophisticated nation-state actor.\n"
    Reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html\n"
    Runbook = "Investigate the resources communicating with the matched IOC for signs of compromise or other malicious activity. Consider rotating credentials on any systems observed communicating with these known malicious systems.\n"
    SummaryAttributes = ["p_any_domain_names", "p_any_ip_addresses", "p_any_sha256_hashes"]
    Tests = i_o_c_sunburst_s_h_a256_i_o_cs_tests

    def rule(self, event):
        return any(ioc_match(event.get("p_any_sha256_hashes"), SUNBURST_SHA256_IOCS))

    def title(self, event):
        hashes = ",".join(ioc_match(event.get("p_any_sha256_hashes"), SUNBURST_SHA256_IOCS))
        return f"Sunburst Indicator of Compromise Detected [SHA256 hash]: {hashes}"
