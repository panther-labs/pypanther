from typing import List

from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_iocs import LOG4J_IP_IOCS, ioc_match

i_o_c_log4_j_i_ps_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Non-matching traffic",
        ExpectedResult=False,
        Log={
            "dstport": 53,
            "dstaddr": "1.1.1.1",
            "srcaddr": "10.0.0.1",
            "p_any_ip_addresses": ["1.1.1.1"],
        },
    ),
    PantherRuleTest(
        Name="Log4j Indicator of Compromise (IP) Detected",
        ExpectedResult=True,
        Log={"srcaddr": "0.0.0.1", "dstaddr": "0.0.0.1", "p_any_ip_addresses": ["0.0.0.1"]},
    ),
]


class IOCLog4JIPs(PantherRule):
    RuleID = "IOC.Log4JIPs-prototype"
    DisplayName = "DEPRECATED -  LOG4J Indicators of Compromise (IP)"
    Enabled = False
    LogTypes = [
        "AWS.ALB",
        "AWS.CloudTrail",
        "AWS.GuardDuty",
        "AWS.S3ServerAccess",
        "AWS.VPCFlow",
        "GCP.AuditLog",
        "Apache.AccessCombined",
        "Apache.AccessCommon",
        "Cloudflare.HttpRequest",
        "Juniper.Access",
        "Nginx.Access",
    ]
    Tags = ["AWS", "DNS", "GCP", "Apache", "Cloudflare", "Nginx", "Juniper", "Deprecated"]
    Severity = Severity.High
    Description = "Deprecated rule. IP addresses involved in LOG4j scanning have been largely recycled at this point, this generates a large amount of false alerts at this point\n"
    Reference = "https://blog.cloudflare.com/actual-cve-2021-44228-payloads-captured-in-the-wild\n"
    Runbook = "Investigate traffic from these IP addresses and look for other IOCs associated with the LOG4J exploit CVE-2021-44228\n"
    SummaryAttributes = ["p_any_domain_names", "p_any_ip_addresses"]
    Tests = i_o_c_log4_j_i_ps_tests

    def rule(self, event):
        return any(ioc_match(event.get("p_any_ip_addresses"), LOG4J_IP_IOCS))

    def title(self, event):
        ips = ",".join(ioc_match(event.get("p_any_ip_addresses"), LOG4J_IP_IOCS))
        return f"IP seen in LOG4J exploit scanning detected IP: {ips}"
