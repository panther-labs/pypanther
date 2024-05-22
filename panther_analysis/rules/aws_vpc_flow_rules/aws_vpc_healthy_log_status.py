from typing import List

from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_base_helpers import aws_rule_context

awsvpc_healthy_log_status_tests: List[PantherRuleTest] = [
    PantherRuleTest(Name="Healthy Log Status", ExpectedResult=False, Log={"log-status": "OK"}),
    PantherRuleTest(
        Name="Unhealthy Log Status", ExpectedResult=True, Log={"log-status": "SKIPDATA"}
    ),
]


class AWSVPCHealthyLogStatus(PantherRule):
    RuleID = "AWS.VPC.HealthyLogStatus-prototype"
    DisplayName = "AWS VPC Healthy Log Status"
    Enabled = True
    LogTypes = ["AWS.VPCFlow"]
    Tags = ["AWS", "Security Control"]
    Severity = Severity.Low
    Description = "Checks for the log status `SKIP-DATA`, which indicates that data was lost either to an internal server error or due to capacity constraints.\n"
    Reference = "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html#flow-log-records"
    Runbook = "Determine if the cause of the issue is capacity constraints, and consider adjusting VPC Flow Log configurations accordingly.\n"
    Tests = awsvpc_healthy_log_status_tests

    def rule(self, event):
        return event.get("log-status") == "SKIPDATA"

    def alert_context(self, event):
        return aws_rule_context(event)
