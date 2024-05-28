from fnmatch import fnmatch
from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.log_types import LogType

awslambdacrud_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Lambda DeleteFunction Unauthorized Account",
        ExpectedResult=True,
        Log={
            "eventVersion": "1.03",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "A1B2C3D4E5F6G7EXAMPLE",
                "arn": "arn:aws:iam::999999999999:user/myUserName",
                "accountId": "999999999999",
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "userName": "myUserName",
            },
            "eventTime": "2015-03-18T19:04:42Z",
            "eventSource": "lambda.amazonaws.com",
            "eventName": "DeleteFunction",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "127.0.0.1",
            "userAgent": "Python-httplib2/0.8 (gzip)",
            "requestParameters": {"functionName": "basic-node-task"},
            "responseElements": None,
            "requestID": "a2198ecc-cda1-11e4-aaa2-e356da31e4ff",
            "eventID": "20b84ce5-730f-482e-b2b2-e8fcc87ceb22",
            "eventType": "AwsApiCall",
            "recipientAccountId": "999999999999",
        },
    ),
    PantherRuleTest(
        Name="Lambda DeleteFunction Unauthorized User",
        ExpectedResult=True,
        Log={
            "eventVersion": "1.03",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "A1B2C3D4E5F6G7EXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/myUserName",
                "accountId": "123456789012",
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "userName": "myUserName",
            },
            "eventTime": "2015-03-18T19:04:42Z",
            "eventSource": "lambda.amazonaws.com",
            "eventName": "DeleteFunction",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "127.0.0.1",
            "userAgent": "Python-httplib2/0.8 (gzip)",
            "requestParameters": {"functionName": "basic-node-task"},
            "responseElements": None,
            "requestID": "a2198ecc-cda1-11e4-aaa2-e356da31e4ff",
            "eventID": "20b84ce5-730f-482e-b2b2-e8fcc87ceb22",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    PantherRuleTest(
        Name="Lambda DeleteFunction Authorized Account",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.03",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "A1B2C3D4E5F6G7EXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/DeployRole",
                "accountId": "123456789012",
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "userName": "myUserName",
            },
            "eventTime": "2015-03-18T19:04:42Z",
            "eventSource": "lambda.amazonaws.com",
            "eventName": "DeleteFunction",
            "awsRegion": "us-west-1",
            "sourceIPAddress": "127.0.0.1",
            "userAgent": "Python-httplib2/0.8 (gzip)",
            "requestParameters": {"functionName": "basic-node-task"},
            "responseElements": None,
            "requestID": "a2198ecc-cda1-11e4-aaa2-e356da31e4ff",
            "eventID": "20b84ce5-730f-482e-b2b2-e8fcc87ceb22",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
]


class AWSLAMBDACRUD(PantherRule):
    RuleID = "AWS.LAMBDA.CRUD-prototype"
    DisplayName = "Lambda CRUD Actions"
    Enabled = False
    LogTypes = [LogType.AWS_CloudTrail]
    Tags = ["AWS", "Security Control", "Configuration Required"]
    Reports = {"CIS": ["3.12"], "MITRE ATT&CK": ["TA0005:T1525"]}
    Severity = PantherSeverity.High
    Description = "Unauthorized lambda Create, Read, Update, or Delete event occurred."
    Runbook = "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html"
    Reference = "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html"
    SummaryAttributes = [
        "eventSource",
        "eventName",
        "recipientAccountId",
        "awsRegion",
        "p_any_aws_arns",
    ]
    Tests = awslambdacrud_tests
    LAMBDA_CRUD_EVENTS = {
        "AddPermission",
        "CreateAlias",
        "CreateEventSourceMapping",
        "CreateFunction",
        "DeleteAlias",
        "DeleteEventSourceMapping",
        "DeleteFunction",
        "PublishVersion",
        "RemovePermission",
        "UpdateAlias",
        "UpdateEventSourceMapping",
        "UpdateFunctionCode",
        "UpdateFunctionConfiguration",
    }
    ALLOWED_ROLES = ["*DeployRole"]

    def rule(self, event):
        if (
            event.get("eventSource") == "lambda.amazonaws.com"
            and event.get("eventName") in self.LAMBDA_CRUD_EVENTS
        ):
            for role in self.ALLOWED_ROLES:
                if fnmatch(deep_get(event, "userIdentity", "arn", default="unknown-arn"), role):
                    return False
            return True
        return False

    def title(self, event):
        return f"[{deep_get(event, 'userIdentity', 'arn', default='unknown-arn')}] performed Lambda [{event.get('eventName')}] in [{event.get('recipientAccountId')} {event.get('awsRegion')}]."

    def dedup(self, event):
        return f"{deep_get(event, 'userIdentity', 'arn', default='unknown-arn')}"

    def alert_context(self, event):
        return aws_rule_context(event)
