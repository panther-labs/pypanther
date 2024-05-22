from typing import List
from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_base_helpers import aws_rule_context, deep_get

a_w_s_cloud_trail_root_failed_console_login_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Root Console Login",
        ExpectedResult=False,
        Log={
            "additionalEventData": {
                "LoginTo": "https://us-west-2.console.aws.amazon.com/console/home?region=us-west-2",
                "MFAUsed": "Yes",
                "MobileVersion": "No",
            },
            "awsRegion": "us-east-1",
            "eventID": "111",
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsConsoleSignIn",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestParameters": None,
            "responseElements": {"ConsoleLogin": "Success"},
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla/5.0 Ti83",
            "userIdentity": {
                "accessKeyId": "",
                "accountId": "123456789012",
                "arn": "arn:aws:iam::123456789012:root",
                "principalId": "123456789012",
                "type": "Root",
            },
        },
    ),
    PantherRuleTest(
        Name="Root Non Console Login",
        ExpectedResult=False,
        Log={
            "additionalEventData": {
                "LoginTo": "https://us-west-2.console.aws.amazon.com/console/home?region=us-west-2",
                "MFAUsed": "Yes",
                "MobileVersion": "No",
            },
            "awsRegion": "us-east-1",
            "eventID": "111",
            "eventName": "NonConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsConsoleSignIn",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestParameters": None,
            "responseElements": {"ConsoleLogin": "Success"},
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla/5.0 Ti83",
            "userIdentity": {
                "accessKeyId": "",
                "accountId": "123456789012",
                "arn": "arn:aws:iam::123456789012:root",
                "principalId": "123456789012",
                "type": "Root",
            },
        },
    ),
    PantherRuleTest(
        Name="Non Root Console Login",
        ExpectedResult=False,
        Log={
            "additionalEventData": {
                "LoginTo": "https://us-west-2.console.aws.amazon.com/console/home?region=us-west-2",
                "MFAUsed": "Yes",
                "MobileVersion": "No",
            },
            "awsRegion": "us-east-1",
            "eventID": "111",
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsConsoleSignIn",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestParameters": None,
            "responseElements": {"ConsoleLogin": "Success"},
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla/5.0 Ti83",
            "userIdentity": {
                "accessKeyId": "",
                "accountId": "123456789012",
                "arn": "arn:aws:iam::123456789012:user/bob",
                "principalId": "123456789012",
                "type": "IAMUser",
            },
        },
    ),
    PantherRuleTest(
        Name="Root Failed Console Login",
        ExpectedResult=True,
        Log={
            "additionalEventData": {
                "LoginTo": "https://us-west-2.console.aws.amazon.com/console/home?region=us-west-2",
                "MFAUsed": "Yes",
                "MobileVersion": "No",
            },
            "awsRegion": "us-east-1",
            "eventID": "111",
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsConsoleSignIn",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestParameters": None,
            "responseElements": {"ConsoleLogin": "Failure"},
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla/5.0 Ti83",
            "userIdentity": {
                "accessKeyId": "",
                "accountId": "123456789012",
                "arn": "arn:aws:iam::123456789012:root",
                "principalId": "123456789012",
                "type": "Root",
            },
        },
    ),
]


class AWSCloudTrailRootFailedConsoleLogin(PantherRule):
    RuleID = "AWS.CloudTrail.RootFailedConsoleLogin-prototype"
    DisplayName = "--DEPRECATED-- Root Account Failed Console Login"
    Enabled = False
    LogTypes = ["AWS.CloudTrail"]
    Tags = ["AWS", "Identity and Access Management", "Initial Access:Valid Accounts"]
    Severity = Severity.High
    Reports = {"MITRE ATT&CK": ["TA0001:T1078"]}
    Description = "Deprecated. Please see AWS.Console.RootLoginFailed instead.\n"
    Runbook = "Verify that the root login attempt was authorized. If not, investigate the root account failed logins to see if there is a pattern.\n"
    Reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"
    SummaryAttributes = [
        "eventName",
        "userAgent",
        "sourceIpAddress",
        "recipientAccountId",
        "p_any_aws_arns",
    ]
    Tests = a_w_s_cloud_trail_root_failed_console_login_tests

    def rule(self, event):
        # Only check console logins
        if event.get("eventName") != "ConsoleLogin":
            return False
        # Only check root activity
        if deep_get(event, "userIdentity", "type") != "Root":
            return False
        # Only alert if the login was a failure
        return deep_get(event, "responseElements", "ConsoleLogin") != "Success"

    def alert_context(self, event):
        return aws_rule_context(event)
