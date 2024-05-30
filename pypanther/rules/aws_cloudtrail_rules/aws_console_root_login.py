from typing import List

from pypanther.base import PantherRule, PantherRuleMock, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_default import lookup_aws_account_name
from pypanther.helpers.panther_oss_helpers import geoinfo_from_ip_formatted
from pypanther.log_types import LogType

aws_console_root_login_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Successful Root Login",
        ExpectedResult=True,
        Mocks=[
            PantherRuleMock(
                ObjectName="geoinfo_from_ip_formatted",
                ReturnValue="111.111.111.111 in SF, California in USA",
            )
        ],
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


class AWSConsoleRootLogin(PantherRule):
    RuleID = "AWS.Console.RootLogin-prototype"
    DisplayName = "Root Console Login"
    DedupPeriodMinutes = 15
    LogTypes = [LogType.AWS_CloudTrail]
    Tags = [
        "AWS",
        "Identity & Access Management",
        "Authentication",
        "DemoThreatHunting",
        "Privilege Escalation:Valid Accounts",
    ]
    Reports = {"CIS": ["3.6"], "MITRE ATT&CK": ["TA0004:T1078"]}
    Severity = PantherSeverity.High
    Description = "The root account has been logged into."
    Runbook = "Investigate the usage of the root account. If this root activity was not authorized, immediately change the root credentials and investigate what actions the root account took.\n"
    Reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"
    SummaryAttributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    Tests = aws_console_root_login_tests

    def rule(self, event):
        return (
            event.get("eventName") == "ConsoleLogin"
            and deep_get(event, "userIdentity", "type") == "Root"
            and (deep_get(event, "responseElements", "ConsoleLogin") == "Success")
        )

    def title(self, event):
        ip_address = event.get("sourceIPAddress")
        return f"AWS root login detected from [{ip_address}] ({geoinfo_from_ip_formatted(ip_address)}) in account [{lookup_aws_account_name(event.get('recipientAccountId'))}]"

    def dedup(self, event):
        # Each Root login should generate a unique alert
        return "-".join(
            [event.get("recipientAccountId"), event.get("eventName"), event.get("eventTime")]
        )

    def alert_context(self, event):
        return {
            "sourceIPAddress": event.get("sourceIPAddress"),
            "userIdentityAccountId": deep_get(event, "userIdentity", "accountId"),
            "userIdentityArn": deep_get(event, "userIdentity", "arn"),
            "eventTime": event.get("eventTime"),
            "mfaUsed": deep_get(event, "additionalEventData", "MFAUsed"),
        }
