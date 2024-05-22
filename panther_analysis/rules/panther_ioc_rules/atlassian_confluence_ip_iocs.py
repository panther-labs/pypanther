from typing import List

from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_iocs import VOLEXITY_CONFLUENCE_IP_IOCS, ioc_match

confluence0_day_i_ps_tests: List[PantherRuleTest] = [
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
        Name="Indicator of Compromise (IP) Detected",
        ExpectedResult=True,
        Log={
            "srcaddr": "59.163.248.170",
            "dstaddr": "0.0.0.1",
            "p_any_ip_addresses": ["59.163.248.170"],
        },
    ),
]


class Confluence0DayIPs(PantherRule):
    RuleID = "Confluence.0DayIPs-prototype"
    DisplayName = "Confluence 0-Day Indicators of Compromise (IOCs)"
    Enabled = True
    LogTypes = [
        "AWS.ALB",
        "AWS.CloudTrail",
        "AWS.GuardDuty",
        "AWS.S3ServerAccess",
        "AWS.VPCFlow",
        "GCP.AuditLog",
        "Apache.AccessCombined",
        "Apache.AccessCommon",
        "Cloudflare.Firewall",
        "Cloudflare.HttpRequest",
        "Juniper.Access",
        "Nginx.Access",
    ]
    Tags = ["AWS", "DNS", "GCP", "Apache", "Cloudflare", "Nginx", "Juniper", "Deprecated"]
    Severity = Severity.High
    Description = "Detects IP addresses observed exploiting the 0-Day CVE-2022-26134\n"
    Reference = "https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/\n"
    Runbook = "Investigate traffic from these IP addresses and look for other IOCs associated with the 0-Day exploit CVE-2022-26134\n"
    SummaryAttributes = ["p_any_domain_names", "p_any_ip_addresses"]
    Tests = confluence0_day_i_ps_tests

    def rule(self, event):
        return any(ioc_match(event.get("p_any_ip_addresses"), VOLEXITY_CONFLUENCE_IP_IOCS))

    def title(self, event):
        ips = ",".join(ioc_match(event.get("p_any_ip_addresses"), VOLEXITY_CONFLUENCE_IP_IOCS))
        return f"IP seen from May 2022 exploitation of Confluence 0-Day: {ips}"
