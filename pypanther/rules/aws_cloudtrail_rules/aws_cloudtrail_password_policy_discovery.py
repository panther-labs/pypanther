from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.log_types import LogType

aws_cloud_trail_password_policy_discovery_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Non-Discovery Event",
        ExpectedResult=False,
        Log={
            "apiversion": "2012-08-10",
            "awsregion": "eu-west-1",
            "eventcategory": "Data",
            "eventid": "5d4b45ed-a15c-41b6-80e9-031729fa060d",
            "eventname": "GetRecords",
            "eventsource": "dynamodb.amazonaws.com",
            "eventtime": "2023-01-10 21:04:02",
            "eventtype": "AwsApiCall",
            "eventversion": "1.08",
            "managementevent": False,
            "useridentity": {"arn": "arn:aws:test_arn"},
        },
    ),
    PantherRuleTest(
        Name="Password Discovery ARN",
        ExpectedResult=True,
        Log={
            "awsregion": "us-east-1",
            "eventcategory": "Management",
            "eventid": "1808ca3b-4311-4b48-9d1f-21061acb2329",
            "eventname": "GetAccountPasswordPolicy",
            "eventsource": "iam.amazonaws.com",
            "eventtime": "2023-01-10 23:10:06",
            "eventtype": "AwsApiCall",
            "eventversion": "1.08",
            "managementevent": True,
            "useridentity": {"arn": "arn:aws:test_arn"},
        },
    ),
    PantherRuleTest(
        Name="Password Discovery Service",
        ExpectedResult=False,
        Log={
            "awsregion": "us-east-1",
            "eventType": "AwsServiceEvent",
            "eventcategory": "Management",
            "eventid": "1808ca3b-4311-4b48-9d1f-21061acb2329",
            "eventname": "GetAccountPasswordPolicy",
            "eventsource": "iam.amazonaws.com",
            "eventtime": "2023-01-10 23:10:06",
            "eventversion": "1.08",
            "managementevent": True,
        },
    ),
]


class AWSCloudTrailPasswordPolicyDiscovery(PantherRule):
    Description = "This detection looks for *AccountPasswordPolicy events in AWS CloudTrail logs. If these events occur in a short period of time from the same ARN, it could constitute Password Policy reconnaissance."
    DisplayName = "AWS CloudTrail Password Policy Discovery"
    Reports = {"MITRE ATT&CK": ["TA0007:T1201"]}
    Reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
    Severity = PantherSeverity.Info
    DedupPeriodMinutes = 30
    LogTypes = [LogType.AWS_CloudTrail]
    RuleID = "AWS.CloudTrail.Password.Policy.Discovery-prototype"
    Threshold = 2
    Tests = aws_cloud_trail_password_policy_discovery_tests
    PASSWORD_DISCOVERY_EVENTS = [
        "GetAccountPasswordPolicy",
        "UpdateAccountPasswordPolicy",
        "PutAccountPasswordPolicy",
    ]

    def rule(self, event):
        service_event = event.get("eventType") == "AwsServiceEvent"
        return event.get("eventName") in self.PASSWORD_DISCOVERY_EVENTS and (not service_event)

    def title(self, event):
        user_arn = deep_get(event, "useridentity", "arn", default="<MISSING_ARN>")
        return f"Password Policy Discovery detected in AWS CloudTrail from [{user_arn}]"

    def alert_context(self, event):
        return aws_rule_context(event)
