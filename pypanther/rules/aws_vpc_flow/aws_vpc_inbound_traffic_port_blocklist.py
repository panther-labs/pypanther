from ipaddress import ip_network

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSVPCInboundPortBlacklist(Rule):
    id = "AWS.VPC.InboundPortBlacklist-prototype"
    display_name = "VPC Flow Logs Inbound Port Blocklist"
    enabled = False
    log_types = [LogType.AWS_VPC_FLOW, LogType.OCSF_NETWORK_ACTIVITY]
    tags = ["AWS", "DataModel", "Configuration Required", "Security Control", "Command and Control:Non-Standard Port"]
    reports = {"MITRE ATT&CK": ["TA0011:T1571"]}
    default_reference = "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"
    default_severity = Severity.HIGH
    default_description = "VPC Flow Logs observed inbound traffic violating the port blocklist.\n"
    default_runbook = "Block the unapproved traffic, or update the unapproved ports list.\n"
    summary_attributes = ["srcaddr", "dstaddr", "dstport"]
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

    tests = [
        RuleTest(
            name="Public to Private IP on Restricted Port",
            expected_result=True,
            log={"dstPort": 22, "dstAddr": "10.0.0.1", "srcAddr": "1.1.1.1", "p_log_type": "AWS.VPCFlow"},
        ),
        RuleTest(
            name="Public to Private IP on Allowed Port",
            expected_result=False,
            log={"dstPort": 443, "dstAddr": "10.0.0.1", "srcAddr": "1.1.1.1", "p_log_type": "AWS.VPCFlow"},
        ),
        RuleTest(
            name="Private to Private IP on Restricted Port",
            expected_result=False,
            log={"dstPort": 22, "dstAddr": "10.0.0.1", "srcAddr": "10.10.10.1", "p_log_type": "AWS.VPCFlow"},
        ),
        RuleTest(
            name="Public to Private IP on Restricted Port - OCSF",
            expected_result=True,
            log={
                "dst_endpoint": {"ip": "10.0.0.1", "port": 22},
                "src_endpoint": {"ip": "1.1.1.1"},
                "p_log_type": "OCSF.NetworkActivity",
            },
        ),
        RuleTest(
            name="Public to Private IP on Allowed Port - OCSF",
            expected_result=False,
            log={
                "dst_endpoint": {"ip": "10.0.0.1", "port": 443},
                "src_endpoint": {"ip": "1.1.1.1"},
                "p_log_type": "OCSF.NetworkActivity",
            },
        ),
    ]
