from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSVPCHealthyLogStatus(Rule):
    id = "AWS.VPC.HealthyLogStatus-prototype"
    display_name = "AWS VPC Healthy Log Status"
    log_types = [LogType.AWS_VPC_FLOW, LogType.OCSF_NETWORK_ACTIVITY]
    tags = ["AWS", "DataModel", "Security Control"]
    default_severity = Severity.LOW
    default_description = "Checks for the log status `SKIP-DATA`, which indicates that data was lost either to an internal server error or due to capacity constraints.\n"
    default_reference = "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html#flow-log-records"
    default_runbook = "Determine if the cause of the issue is capacity constraints, and consider adjusting VPC Flow Log configurations accordingly.\n"

    def rule(self, event):
        return event.udm("log_status") == "SKIPDATA"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Healthy Log Status",
            expected_result=False,
            log={"log-status": "OK", "p_log_type": "AWS.VPCFlow"},
        ),
        RuleTest(
            name="Unhealthy Log Status",
            expected_result=True,
            log={"log-status": "SKIPDATA", "p_log_type": "AWS.VPCFlow"},
        ),
        RuleTest(
            name="Healthy Log Status - OCSF",
            expected_result=False,
            log={"status_code": "OK", "p_log_type": "OCSF.NetworkActivity"},
        ),
        RuleTest(
            name="Unhealthy Log Status - OCSF",
            expected_result=True,
            log={"status_code": "SKIPDATA", "p_log_type": "OCSF.NetworkActivity"},
        ),
    ]
