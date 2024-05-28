from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context
from pypanther.log_types import LogType

awsip_set_modified_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="CreateIPSet Event",
        ExpectedResult=True,
        Log={
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
    PantherRuleTest(
        Name="UpdateIPSet",
        ExpectedResult=True,
        Log={
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
    PantherRuleTest(
        Name="NotIPSet",
        ExpectedResult=False,
        Log={
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


class AWSIPSetModified(PantherRule):
    Description = "Detects creation and updates of the list of trusted IPs used by GuardDuty and WAF. Potentially to disable security alerts against malicious IPs."
    DisplayName = "AWS Trusted IPSet Modified"
    Reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    Reference = "https://docs.aws.amazon.com/managedservices/latest/ctref/management-monitoring-guardduty-ip-set-update-review-required.html"
    Severity = PantherSeverity.High
    LogTypes = [LogType.AWS_CloudTrail]
    RuleID = "AWS.IPSet.Modified-prototype"
    Tests = awsip_set_modified_tests
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
