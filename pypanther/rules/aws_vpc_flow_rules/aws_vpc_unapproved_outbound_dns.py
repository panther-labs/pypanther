from ipaddress import ip_network
from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context
from pypanther.log_types import LogType

awsvpc_unapproved_outbound_dns_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Approved Outbound DNS Traffic",
        ExpectedResult=False,
        Log={"dstport": 53, "dstaddr": "1.1.1.1", "srcaddr": "10.0.0.1"},
    ),
    PantherRuleTest(
        Name="Unapproved Outbound DNS Traffic",
        ExpectedResult=True,
        Log={"dstport": 53, "dstaddr": "100.100.100.100", "srcaddr": "10.0.0.1"},
    ),
    PantherRuleTest(
        Name="Outbound Non-DNS Traffic",
        ExpectedResult=False,
        Log={"dstport": 80, "dstaddr": "100.100.100.100", "srcaddr": "10.0.0.1"},
    ),
]


class AWSVPCUnapprovedOutboundDNS(PantherRule):
    RuleID = "AWS.VPC.UnapprovedOutboundDNS-prototype"
    DisplayName = "VPC Flow Logs Unapproved Outbound DNS Traffic"
    Enabled = False
    LogTypes = [LogType.AWS_VPCFlow]
    Tags = [
        "AWS",
        "Configuration Required",
        "Security Control",
        "Command and Control:Application Layer Protocol",
    ]
    Reports = {"MITRE ATT&CK": ["TA0011:T1071"]}
    Reference = "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"
    Severity = PantherSeverity.Medium
    Description = "Alerts if outbound DNS traffic is detected to a non-approved DNS server. DNS is often used as a means to exfiltrate data or perform command and control for compromised hosts. All DNS traffic should be routed through internal DNS servers or trusted 3rd parties.\n"
    Runbook = "Investigate the host sending unapproved DNS activity for signs of compromise or other malicious activity. Update network configurations appropriately to ensure all DNS traffic is routed to approved DNS servers.\n"
    SummaryAttributes = ["srcaddr", "dstaddr", "dstport"]
    Tests = awsvpc_unapproved_outbound_dns_tests  # CloudFlare DNS
    # Google DNS
    # '10.0.0.1', # Internal DNS
    APPROVED_DNS_SERVERS = {"1.1.1.1", "8.8.8.8"}

    def rule(self, event):
        # Common DNS ports, for better security use an application layer aware network monitor
        #
        # Defaults to True (no alert) if 'dstport' key is not present
        if event.get("dstport") != 53 and event.get("dstport") != 5353:
            return False
        # Only monitor traffic that is originating internally
        #
        # Defaults to True (no alert) if 'srcaddr' key is not present
        if ip_network(event.get("srcaddr", "0.0.0.0/32")).is_global:
            return False
        # No clean way to default to False (no alert), so explicitly check for key
        return "dstaddr" in event and event.get("dstaddr") not in self.APPROVED_DNS_SERVERS

    def alert_context(self, event):
        return aws_rule_context(event)
