from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSIPSetModified(Rule):
    default_description = "Detects creation and updates of the list of trusted IPs used by GuardDuty and WAF. Potentially to disable security alerts against malicious IPs."
    display_name = "AWS Trusted IPSet Modified"
    reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    default_reference = "https://docs.aws.amazon.com/managedservices/latest/ctref/management-monitoring-guardduty-ip-set-update-review-required.html"
    default_severity = Severity.HIGH
    log_types = [LogType.AWS_CLOUDTRAIL]
    id = "AWS.IPSet.Modified-prototype"
    IPSET_ACTIONS = ["CreateIPSet", "UpdateIPSet"]

    def rule(self, event):
        if (
            event.get("eventSource", "") == "guardduty.amazonaws.com"
            or event.get("eventSource", "") == "wafv2.amazonaws.com"
        ):
            if event.get("eventName", "") in self.IPSET_ACTIONS:
                return True
        return False

    def title(self, event):
        return f"IPSet was modified in [{event.get('recipientAccountId', '')}]"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="CreateIPSet Event",
            expected_result=True,
            log={
                "awsregion": "us-east-1",
                "eventid": "abc-123",
                "eventname": "CreateIPSet",
                "eventsource": "guardduty.amazonaws.com",
                "eventtime": "2022-07-17 04:50:23",
                "eventtype": "AwsApiCall",
                "eventversion": "1.08",
                "p_any_aws_instance_ids": ["testinstanceid"],
                "p_event_time": "2022-07-17 04:50:23",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2022-07-17 04:55:11.788",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="UpdateIPSet",
            expected_result=True,
            log={
                "awsregion": "us-east-1",
                "eventid": "abc-123",
                "eventname": "CreateIPSet",
                "eventsource": "guardduty.amazonaws.com",
                "eventtime": "2022-07-17 04:50:23",
                "eventtype": "AwsApiCall",
                "eventversion": "1.08",
                "p_any_aws_instance_ids": ["testinstanceid"],
                "p_event_time": "2022-07-17 04:50:23",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2022-07-17 04:55:11.788",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="NotIPSet",
            expected_result=False,
            log={
                "awsregion": "us-east-1",
                "eventid": "abc-123",
                "eventname": "ModifyInstanceAttributes",
                "eventsource": "guardduty.amazonaws.com",
                "eventtime": "2022-07-17 04:50:23",
                "eventtype": "AwsApiCall",
                "eventversion": "1.08",
                "p_any_aws_instance_ids": ["testinstanceid"],
                "p_event_time": "2022-07-17 04:50:23",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2022-07-17 04:55:11.788",
                "recipientAccountId": "123456789012",
            },
        ),
    ]
