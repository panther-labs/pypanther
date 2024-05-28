from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.helpers.panther_default import lookup_aws_account_name
from pypanther.log_types import LogType

aws_console_root_login_failed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Failed Root Login",
        ExpectedResult=True,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "Root",
                "principalId": "1111",
                "arn": "arn:aws:iam::123456789012:root",
                "accountId": "123456789012",
                "userName": "root",
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla",
            "requestParameters": None,
            "responseElements": {"ConsoleLogin": "Failure"},
            "additionalEventData": {
                "LoginTo": "https://console.aws.amazon.com/console/",
                "MobileVersion": "No",
                "MFAUsed": "No",
            },
            "eventID": "1",
            "eventType": "AwsConsoleSignIn",
            "recipientAccountId": "123456789012",
        },
    ),
    PantherRuleTest(
        Name="Successful Login",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "Root",
                "principalId": "1111",
                "arn": "arn:aws:iam::123456789012:root",
                "accountId": "123456789012",
                "userName": "root",
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla",
            "requestParameters": None,
            "responseElements": {"ConsoleLogin": "Success"},
            "additionalEventData": {
                "LoginTo": "https://console.aws.amazon.com/console/",
                "MobileVersion": "No",
                "MFAUsed": "No",
            },
            "eventID": "1",
            "eventType": "AwsConsoleSignIn",
            "recipientAccountId": "123456789012",
        },
    ),
    PantherRuleTest(
        Name="Non-Login Event",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.06",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:user/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "1111",
                        "arn": "arn:aws:iam::123456789012:user/tester",
                        "accountId": "123456789012",
                        "userName": "tester",
                    },
                    "attributes": {
                        "creationDate": "2019-01-01T00:00:00Z",
                        "mfaAuthenticated": "true",
                    },
                },
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "dynamodb.amazonaws.com",
            "eventName": "DescribeTable",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.amazonaws.com",
            "requestParameters": {"tableName": "table"},
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "readOnly": True,
            "resources": [
                {
                    "accountId": "123456789012",
                    "type": "AWS::DynamoDB::Table",
                    "ARN": "arn::::table/table",
                }
            ],
            "eventType": "AwsApiCall",
            "apiVersion": "2012-08-10",
            "managementEvent": True,
            "recipientAccountId": "123456789012",
        },
    ),
]


class AWSConsoleRootLoginFailed(PantherRule):
    RuleID = "AWS.Console.RootLoginFailed-prototype"
    DisplayName = "Failed Root Console Login"
    DedupPeriodMinutes = 15
    LogTypes = [LogType.AWS_CloudTrail]
    Tags = [
        "AWS",
        "Identity & Access Management",
        "Authentication",
        "DemoThreatHunting",
        "Credential Access:Brute Force",
    ]
    Threshold = 5
    Reports = {"CIS": ["3.6"], "MITRE ATT&CK": ["TA0006:T1110"]}
    Severity = PantherSeverity.High
    Description = "A Root console login failed."
    Runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-console-login-failed"
    Reference = "https://amzn.to/3aMSmTd"
    SummaryAttributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    Tests = aws_console_root_login_failed_tests

    def rule(self, event):
        return (
            event.get("eventName") == "ConsoleLogin"
            and deep_get(event, "userIdentity", "type") == "Root"
            and (deep_get(event, "responseElements", "ConsoleLogin") == "Failure")
        )

    def title(self, event):
        return f"AWS root login failed from [{event.get('sourceIPAddress')}] in account [{lookup_aws_account_name(event.get('recipientAccountId'))}]"

    def alert_context(self, event):
        return aws_rule_context(event)
