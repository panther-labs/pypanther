from ipaddress import ip_network
from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context
from pypanther.log_types import PantherLogType

awsvpc_unapproved_outbound_dns_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Approved Outbound DNS Traffic",
        ExpectedResult=False,
        Log={
            "dstPort": 53,
            "dstAddr": "1.1.1.1",
            "srcAddr": "10.0.0.1",
            "p_log_type": "AWS.VPCFlow",
        },
    ),
    PantherRuleTest(
        Name="Unapproved Outbound DNS Traffic",
        ExpectedResult=True,
        Log={
            "dstPort": 53,
            "dstAddr": "100.100.100.100",
            "srcAddr": "10.0.0.1",
            "p_log_type": "AWS.VPCFlow",
        },
    ),
    PantherRuleTest(
        Name="Outbound Non-DNS Traffic",
        ExpectedResult=False,
        Log={
            "dstPort": 80,
            "dstAddr": "100.100.100.100",
            "srcAddr": "10.0.0.1",
            "p_log_type": "AWS.VPCFlow",
        },
    ),
    PantherRuleTest(
        Name="Approved Outbound DNS Traffic - OCSF",
        ExpectedResult=False,
        Log={
            "dst_endpoint": {"ip": "1.1.1.1", "port": 53},
            "src_endpoint": {"ip": "10.0.0.1"},
            "p_log_type": "OCSF.NetworkActivity",
        },
    ),
    PantherRuleTest(
        Name="Unapproved Outbound DNS Traffic - OCSF",
        ExpectedResult=True,
        Log={
            "dst_endpoint": {"ip": "100.100.100.100", "port": 53},
            "src_endpoint": {"ip": "10.0.0.1"},
            "p_log_type": "OCSF.NetworkActivity",
        },
    ),
]


class AWSVPCUnapprovedOutboundDNS(PantherRule):
    RuleID = "AWS.VPC.UnapprovedOutboundDNS-prototype"
    DisplayName = "VPC Flow Logs Unapproved Outbound DNS Traffic"
    Enabled = False
    LogTypes = [PantherLogType.AWS_VPCFlow, PantherLogType.OCSF_NetworkActivity]
    Tags = [
        "AWS",
        "DataModel",
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
        if event.udm("destination_port") != 53 and event.udm("destination_port") != 5353:
            return False
        # Only monitor traffic that is originating internally
        #
        # Defaults to True (no alert) if 'srcaddr' key is not present
        source_ip = event.udm("source_ip") or "0.0.0.0/32"
        if ip_network(source_ip).is_global:
            return False
        # No clean way to default to False (no alert), so explicitly check for key
        return (
            bool(event.udm("destination_ip"))
            and event.udm("destination_ip") not in self.APPROVED_DNS_SERVERS
        )

    def alert_context(self, event):
        return aws_rule_context(event)
