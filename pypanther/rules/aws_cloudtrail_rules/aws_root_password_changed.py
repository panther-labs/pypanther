from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.log_types import LogType

aws_cloud_trail_root_password_changed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Root Password Changed",
        ExpectedResult=True,
        Log={
            "awsRegion": "us-east-1",
            "eventID": "1111",
            "eventName": "PasswordUpdated",
            "eventSource": "signin.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsConsoleSignIn",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": None,
            "responseElements": {"PasswordUpdated": "Success"},
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36",
            "userIdentity": {
                "accesKeyId": "1111",
                "accessKeyId": "",
                "accountId": "123456789012",
                "arn": "arn:aws:iam::123456789012:root",
                "principalId": "123456789012",
                "type": "Root",
            },
        },
    ),
    PantherRuleTest(
        Name="Root Password Change Failed",
        ExpectedResult=False,
        Log={
            "awsRegion": "us-east-1",
            "eventID": "1111",
            "eventName": "PasswordUpdated",
            "eventSource": "signin.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsConsoleSignIn",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": None,
            "responseElements": {"PasswordUpdated": "Failure"},
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36",
            "userIdentity": {
                "accesKeyId": "1111",
                "accessKeyId": "",
                "accountId": "123456789012",
                "arn": "arn:aws:iam::123456789012:root",
                "principalId": "123456789012",
                "type": "Root",
            },
        },
    ),
]


class AWSCloudTrailRootPasswordChanged(PantherRule):
    RuleID = "AWS.CloudTrail.RootPasswordChanged-prototype"
    DisplayName = "Root Password Changed"
    LogTypes = [LogType.AWS_CloudTrail]
    Tags = ["AWS", "Identity and Access Management", "Persistence:Account Manipulation"]
    Severity = PantherSeverity.High
    Reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    Description = "Someone manually changed the Root console login password.\n"
    Runbook = "Verify that the root password change was authorized. If not, AWS support should be contacted immediately as the root account cannot be recovered through normal means and grants complete access to the account.\n"
    Reference = (
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_change-root.html"
    )
    SummaryAttributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    Tests = aws_cloud_trail_root_password_changed_tests

    def rule(self, event):
        # Only check password update changes
        if event.get("eventName") != "PasswordUpdated":
            return False
        # Only check root activity
        if deep_get(event, "userIdentity", "type") != "Root":
            return False
        # Only alert if the login was a success
        return deep_get(event, "responseElements", "PasswordUpdated") == "Success"

    def alert_context(self, event):
        return aws_rule_context(event)
