from ipaddress import ip_network

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSVPCSSHAllowedSignal(Rule):
    id = "AWS.VPC.SSHAllowedSignal-prototype"
    display_name = "Signal - VPC Flow Logs Allowed SSH"
    create_alert = False
    log_types = [LogType.AWS_VPC_FLOW]
    tags = ["AWS", "Signal"]
    reports = {"MITRE ATT&CK": ["TA0008:T1021.004"]}
    default_severity = Severity.INFO
    default_description = (
        "VPC Flow Logs observed inbound traffic on SSH port. This rule is a signal to be used in correlation rules.\n"
    )

    def rule(self, event):
        # Defaults to True (no alert) if 'dstport' is not present
        if event.udm("destination_port") != 22 or event.get("action") != "ACCEPT":
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
            name="Public to Private IP on SSH Allowed",
            expected_result=True,
            log={
                "dstPort": 22,
                "dstAddr": "10.0.0.1",
                "srcAddr": "1.1.1.1",
                "instanceId": "i-0d4c7318592c6a2c7",
                "action": "ACCEPT",
                "p_log_type": "AWS.VPCFlow",
            },
        ),
        RuleTest(
            name="Public to Private IP on non-SSH",
            expected_result=False,
            log={
                "dstPort": 443,
                "dstAddr": "10.0.0.1",
                "srcAddr": "1.1.1.1",
                "instanceId": "i-0d4c7318592c6a2c7",
                "action": "ACCEPT",
                "p_log_type": "AWS.VPCFlow",
            },
        ),
        RuleTest(
            name="Private to Private IP on SSH",
            expected_result=False,
            log={
                "dstPort": 22,
                "dstAddr": "10.0.0.1",
                "srcAddr": "10.10.10.1",
                "instanceId": "i-0d4c7318592c6a2c7",
                "action": "ACCEPT",
                "p_log_type": "AWS.VPCFlow",
            },
        ),
        RuleTest(
            name="Public to Private IP on SSH Denied",
            expected_result=False,
            log={
                "dstPort": 22,
                "dstAddr": "10.0.0.1",
                "srcAddr": "1.1.1.1",
                "instanceId": "i-0d4c7318592c6a2c7",
                "action": "REJECT",
                "p_log_type": "AWS.VPCFlow",
            },
        ),
    ]
