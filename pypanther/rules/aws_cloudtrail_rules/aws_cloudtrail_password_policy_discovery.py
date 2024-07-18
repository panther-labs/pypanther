from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get

aws_cloud_trail_password_policy_discovery_tests: list[RuleTest] = [
    RuleTest(
        name="Non-Discovery Event",
        expected_result=False,
        log={
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
    RuleTest(
        name="Password Discovery ARN",
        expected_result=True,
        log={
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
    RuleTest(
        name="Password Discovery Service",
        expected_result=False,
        log={
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


@panther_managed
class AWSCloudTrailPasswordPolicyDiscovery(Rule):
    default_description = "This detection looks for *AccountPasswordPolicy events in AWS CloudTrail logs. If these events occur in a short period of time from the same ARN, it could constitute Password Policy reconnaissance."
    display_name = "AWS CloudTrail Password Policy Discovery"
    reports = {"MITRE ATT&CK": ["TA0007:T1201"]}
    default_reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
    default_severity = Severity.INFO
    dedup_period_minutes = 30
    log_types = [LogType.AWS_CLOUDTRAIL]
    id = "AWS.CloudTrail.Password.Policy.Discovery-prototype"
    threshold = 2
    tests = aws_cloud_trail_password_policy_discovery_tests
    PASSWORD_DISCOVERY_EVENTS = ["GetAccountPasswordPolicy", "UpdateAccountPasswordPolicy", "PutAccountPasswordPolicy"]

    def rule(self, event):
        service_event = event.get("eventType") == "AwsServiceEvent"
        return event.get("eventName") in self.PASSWORD_DISCOVERY_EVENTS and (not service_event)

    def title(self, event):
        user_arn = deep_get(event, "useridentity", "arn", default="<MISSING_ARN>")
        return f"Password Policy Discovery detected in AWS CloudTrail from [{user_arn}]"

    def alert_context(self, event):
        return aws_rule_context(event)
