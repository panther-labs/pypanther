from ipaddress import ip_network
from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context
from pypanther.log_types import LogType

awsvpc_inbound_port_blacklist_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Public to Private IP on Restricted Port",
        ExpectedResult=True,
        Log={"dstport": 22, "dstaddr": "10.0.0.1", "srcaddr": "1.1.1.1"},
    ),
    PantherRuleTest(
        Name="Public to Private IP on Allowed Port",
        ExpectedResult=False,
        Log={"dstport": 443, "dstaddr": "10.0.0.1", "srcaddr": "1.1.1.1"},
    ),
    PantherRuleTest(
        Name="Private to Private IP on Restricted Port",
        ExpectedResult=False,
        Log={"dstport": 22, "dstaddr": "10.0.0.1", "srcaddr": "10.10.10.1"},
    ),
]


class AWSVPCInboundPortBlacklist(PantherRule):
    RuleID = "AWS.VPC.InboundPortBlacklist-prototype"
    DisplayName = "VPC Flow Logs Inbound Port Blocklist"
    Enabled = False
    LogTypes = [LogType.AWS_VPCFlow]
    Tags = [
        "AWS",
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
        if event.get("dstport") not in self.CONTROLLED_PORTS:
            return False
        # Only monitor for traffic coming from non-private IP space
        #
        # Defaults to True (no alert) if 'srcaddr' key is not present
        if not ip_network(event.get("srcaddr", "0.0.0.0/32")).is_global:
            return False
        # Alert if the traffic is destined for internal IP addresses
        #
        # Defaults to False(no alert) if 'dstaddr' key is not present
        return not ip_network(event.get("dstaddr", "1.0.0.0/32")).is_global

    def alert_context(self, event):
        return aws_rule_context(event)
