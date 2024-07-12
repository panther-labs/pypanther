from typing import List

from pypanther import PantherLogType, PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context

awsvpc_healthy_log_status_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        name="Healthy Log Status",
        expected_result=False,
        log={"log-status": "OK", "p_log_type": "AWS.VPCFlow"},
    ),
    PantherRuleTest(
        name="Unhealthy Log Status",
        expected_result=True,
        log={"log-status": "SKIPDATA", "p_log_type": "AWS.VPCFlow"},
    ),
    PantherRuleTest(
        name="Healthy Log Status - OCSF",
        expected_result=False,
        log={"status_code": "OK", "p_log_type": "OCSF.NetworkActivity"},
    ),
    PantherRuleTest(
        name="Unhealthy Log Status - OCSF",
        expected_result=True,
        log={"status_code": "SKIPDATA", "p_log_type": "OCSF.NetworkActivity"},
    ),
]


class AWSVPCHealthyLogStatus(PantherRule):
    id_ = "AWS.VPC.HealthyLogStatus-prototype"
    display_name = "AWS VPC Healthy Log Status"
    log_types = [PantherLogType.AWS_VPCFlow, PantherLogType.OCSF_NetworkActivity]
    tags = ["AWS", "DataModel", "Security Control"]
    default_severity = PantherSeverity.low
    default_description = "Checks for the log status `SKIP-DATA`, which indicates that data was lost either to an internal server error or due to capacity constraints.\n"
    default_reference = (
        "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html#flow-log-records"
    )
    default_runbook = "Determine if the cause of the issue is capacity constraints, and consider adjusting VPC Flow Log configurations accordingly.\n"
    tests = awsvpc_healthy_log_status_tests

    def rule(self, event):
        return event.udm("log_status") == "SKIPDATA"

    def alert_context(self, event):
        return aws_rule_context(event)
