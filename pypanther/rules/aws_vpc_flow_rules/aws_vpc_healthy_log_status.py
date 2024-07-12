from typing import List

from pypanther import PantherLogType, PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context

awsvpc_healthy_log_status_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Healthy Log Status", ExpectedResult=False, Log={"log-status": "OK", "p_log_type": "AWS.VPCFlow"}
    ),
    PantherRuleTest(
        Name="Unhealthy Log Status", ExpectedResult=True, Log={"log-status": "SKIPDATA", "p_log_type": "AWS.VPCFlow"}
    ),
    PantherRuleTest(
        Name="Healthy Log Status - OCSF",
        ExpectedResult=False,
        Log={"status_code": "OK", "p_log_type": "OCSF.NetworkActivity"},
    ),
    PantherRuleTest(
        Name="Unhealthy Log Status - OCSF",
        ExpectedResult=True,
        Log={"status_code": "SKIPDATA", "p_log_type": "OCSF.NetworkActivity"},
    ),
]


class AWSVPCHealthyLogStatus(PantherRule):
    RuleID = "AWS.VPC.HealthyLogStatus-prototype"
    DisplayName = "AWS VPC Healthy Log Status"
    LogTypes = [PantherLogType.AWS_VPCFlow, PantherLogType.OCSF_NetworkActivity]
    Tags = ["AWS", "DataModel", "Security Control"]
    Severity = PantherSeverity.Low
    Description = "Checks for the log status `SKIP-DATA`, which indicates that data was lost either to an internal server error or due to capacity constraints.\n"
    Reference = "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html#flow-log-records"
    Runbook = "Determine if the cause of the issue is capacity constraints, and consider adjusting VPC Flow Log configurations accordingly.\n"
    Tests = awsvpc_healthy_log_status_tests

    def rule(self, event):
        return event.udm("log_status") == "SKIPDATA"

    def alert_context(self, event):
        return aws_rule_context(event)
