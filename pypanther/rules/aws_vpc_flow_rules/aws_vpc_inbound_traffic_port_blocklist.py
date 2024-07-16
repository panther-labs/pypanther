from ipaddress import ip_network
from typing import List

from pypanther import PantherLogType, PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context

awsvpc_inbound_port_blacklist_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Public to Private IP on Restricted Port",
        ExpectedResult=True,
        Log={
            "dstPort": 22,
            "dstAddr": "10.0.0.1",
            "srcAddr": "1.1.1.1",
            "p_log_type": "AWS.VPCFlow",
        },
    ),
    PantherRuleTest(
        Name="Public to Private IP on Allowed Port",
        ExpectedResult=False,
        Log={
            "dstPort": 443,
            "dstAddr": "10.0.0.1",
            "srcAddr": "1.1.1.1",
            "p_log_type": "AWS.VPCFlow",
        },
    ),
    PantherRuleTest(
        Name="Private to Private IP on Restricted Port",
        ExpectedResult=False,
        Log={
            "dstPort": 22,
            "dstAddr": "10.0.0.1",
            "srcAddr": "10.10.10.1",
            "p_log_type": "AWS.VPCFlow",
        },
    ),
    PantherRuleTest(
        Name="Public to Private IP on Restricted Port - OCSF",
        ExpectedResult=True,
        Log={
            "dst_endpoint": {"ip": "10.0.0.1", "port": 22},
            "src_endpoint": {"ip": "1.1.1.1"},
            "p_log_type": "OCSF.NetworkActivity",
        },
    ),
    PantherRuleTest(
        Name="Public to Private IP on Allowed Port - OCSF",
        ExpectedResult=False,
        Log={
            "dst_endpoint": {"ip": "10.0.0.1", "port": 443},
            "src_endpoint": {"ip": "1.1.1.1"},
            "p_log_type": "OCSF.NetworkActivity",
        },
    ),
]


class AWSVPCInboundPortBlacklist(PantherRule):
    RuleID = "AWS.VPC.InboundPortBlacklist-prototype"
    DisplayName = "VPC Flow Logs Inbound Port Blocklist"
    Enabled = False
    LogTypes = [PantherLogType.AWS_VPCFlow, PantherLogType.OCSF_NetworkActivity]
    Tags = [
        "AWS",
        "DataModel",
        "Configuration Required",
        "Security Control",
        "Command and Control:Non-Standard Port",
    ]
    Reports = {"MITRE ATT&CK": ["TA0011:T1571"]}
    Reference = "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"
    Severity = PantherSeverity.High
    Description = "VPC Flow Logs observed inbound traffic violating the port blocklist.\n"
    Runbook = "Block the unapproved traffic, or update the unapproved ports list.\n"
    SummaryAttributes = ["srcaddr", "dstaddr", "dstport"]
    Tests = awsvpc_inbound_port_blacklist_tests
    CONTROLLED_PORTS = {22, 3389}

    def rule(self, event):
        # Only monitor for blocklisted ports
        #
        # Defaults to True (no alert) if 'dstport' is not present
        if event.udm("destination_port") not in self.CONTROLLED_PORTS:
            return False
        # Only monitor for traffic coming from non-private IP space
        #
        # Defaults to True (no alert) if 'srcaddr' key is not present
        source_ip = event.udm("source_ip") or "0.0.0.0/32"
        if not ip_network(source_ip).is_global:
            return False
        # Alert if the traffic is destined for internal IP addresses
        #
        # Defaults to False(no alert) if 'dstaddr' key is not present
        destination_ip = event.udm("destination_ip") or "1.0.0.0/32"
        return not ip_network(destination_ip).is_global

    def alert_context(self, event):
        return aws_rule_context(event)
