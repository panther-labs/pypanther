from ipaddress import ip_network

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context

awsvpc_unapproved_outbound_dns_tests: list[RuleTest] = [
    RuleTest(
        name="Approved Outbound DNS Traffic",
        expected_result=False,
        log={"dstPort": 53, "dstAddr": "1.1.1.1", "srcAddr": "10.0.0.1", "p_log_type": "AWS.VPCFlow"},
    ),
    RuleTest(
        name="Unapproved Outbound DNS Traffic",
        expected_result=True,
        log={"dstPort": 53, "dstAddr": "100.100.100.100", "srcAddr": "10.0.0.1", "p_log_type": "AWS.VPCFlow"},
    ),
    RuleTest(
        name="Outbound Non-DNS Traffic",
        expected_result=False,
        log={"dstPort": 80, "dstAddr": "100.100.100.100", "srcAddr": "10.0.0.1", "p_log_type": "AWS.VPCFlow"},
    ),
    RuleTest(
        name="Approved Outbound DNS Traffic - OCSF",
        expected_result=False,
        log={
            "dst_endpoint": {"ip": "1.1.1.1", "port": 53},
            "src_endpoint": {"ip": "10.0.0.1"},
            "p_log_type": "OCSF.NetworkActivity",
        },
    ),
    RuleTest(
        name="Unapproved Outbound DNS Traffic - OCSF",
        expected_result=True,
        log={
            "dst_endpoint": {"ip": "100.100.100.100", "port": 53},
            "src_endpoint": {"ip": "10.0.0.1"},
            "p_log_type": "OCSF.NetworkActivity",
        },
    ),
]


@panther_managed
class AWSVPCUnapprovedOutboundDNS(Rule):
    id = "AWS.VPC.UnapprovedOutboundDNS-prototype"
    display_name = "VPC Flow Logs Unapproved Outbound DNS Traffic"
    enabled = False
    log_types = [LogType.AWS_VPC_FLOW, LogType.OCSF_NETWORK_ACTIVITY]
    tags = [
        "AWS",
        "DataModel",
        "Configuration Required",
        "Security Control",
        "Command and Control:Application Layer Protocol",
    ]
    reports = {"MITRE ATT&CK": ["TA0011:T1071"]}
    default_reference = "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"
    default_severity = Severity.MEDIUM
    default_description = "Alerts if outbound DNS traffic is detected to a non-approved DNS server. DNS is often used as a means to exfiltrate data or perform command and control for compromised hosts. All DNS traffic should be routed through internal DNS servers or trusted 3rd parties.\n"
    default_runbook = "Investigate the host sending unapproved DNS activity for signs of compromise or other malicious activity. Update network configurations appropriately to ensure all DNS traffic is routed to approved DNS servers.\n"
    summary_attributes = ["srcaddr", "dstaddr", "dstport"]
    tests = awsvpc_unapproved_outbound_dns_tests  # CloudFlare DNS
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
        return bool(event.udm("destination_ip")) and event.udm("destination_ip") not in self.APPROVED_DNS_SERVERS

    def alert_context(self, event):
        return aws_rule_context(event)
