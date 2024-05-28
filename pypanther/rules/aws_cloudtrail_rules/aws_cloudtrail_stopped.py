from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.helpers.panther_default import aws_cloudtrail_success, lookup_aws_account_name
from pypanther.log_types import LogType

aws_cloud_trail_stopped_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="CloudTrail Was Stopped",
        ExpectedResult=True,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "1111",
                        "arn": "arn:aws:iam::123456789012:role/tester",
                        "accountId": "123456789012",
                        "userName": "Tester",
                    },
                    "webIdFederationData": {},
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-01-01T00:00:00Z",
                    },
                },
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "cloudtrail.amazonaws.com",
            "eventName": "StopLogging",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.amazonaws.com",
            "requestParameters": {
                "name": "arn:aws:cloudtrail:us-west-2:123456789012:trail/example-trail"
            },
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "readOnly": False,
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    PantherRuleTest(
        Name="CloudTrail Was Started",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "111:panther-snapshot-scheduler",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "false",
                        "creationDate": "2019-01-01T00:00:00Z",
                    },
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "1111",
                        "arn": "arn:aws:iam::123456789012:role/tester",
                        "accountId": "123456789012",
                        "userName": "tester",
                    },
                },
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "cloudtrail.amazonaws.com",
            "eventName": "StartLogging",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla",
            "requestParameters": {
                "encryptionContext": {
                    "aws:lambda:FunctionArn": "arn:aws:lambda:us-west-2:123456789012:function:test-function"
                }
            },
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "readOnly": True,
            "resources": [
                {
                    "ARN": "arn:aws:kms:us-west-2:123456789012:key/1",
                    "accountId": "123456789012",
                    "type": "AWS::KMS::Key",
                }
            ],
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    PantherRuleTest(
        Name="Error Stopping CloudTrail",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.05",
            "errorCode": "InvalidTrailNameException",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "1111",
                        "arn": "arn:aws:iam::123456789012:role/tester",
                        "accountId": "123456789012",
                        "userName": "Tester",
                    },
                    "webIdFederationData": {},
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-01-01T00:00:00Z",
                    },
                },
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "cloudtrail.amazonaws.com",
            "eventName": "StopLogging",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.amazonaws.com",
            "requestParameters": {
                "name": "arn:aws:cloudtrail:us-west-2:123456789012:trail/example-trail"
            },
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "readOnly": False,
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
]


class AWSCloudTrailStopped(PantherRule):
    RuleID = "AWS.CloudTrail.Stopped-prototype"
    DisplayName = "CloudTrail Stopped"
    LogTypes = [LogType.AWS_CloudTrail]
    Tags = ["AWS", "Security Control", "DemoThreatHunting", "Defense Evasion:Impair Defenses"]
    Reports = {"CIS": ["3.5"], "MITRE ATT&CK": ["TA0005:T1562"]}
    Severity = PantherSeverity.Medium
    Description = "A CloudTrail Trail was modified.\n"
    Runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-cloudtrail-modified"
    Reference = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-delete-trails-console.html"
    SummaryAttributes = [
        "eventName",
        "userAgent",
        "sourceIpAddress",
        "recipientAccountId",
        "p_any_aws_arns",
    ]
    Tests = aws_cloud_trail_stopped_tests
    # API calls that are indicative of CloudTrail changes
    CLOUDTRAIL_STOP_DELETE = {"DeleteTrail", "StopLogging"}

    def rule(self, event):
        return (
            aws_cloudtrail_success(event) and event.get("eventName") in self.CLOUDTRAIL_STOP_DELETE
        )

    def dedup(self, event):
        # Merge on the CloudTrail ARN
        return deep_get(event, "requestParameters", "name", default="<UNKNOWN_NAME>")

    def title(self, event):
        return f"CloudTrail [{self.dedup(event)}] in account [{lookup_aws_account_name(event.get('recipientAccountId'))}] was stopped/deleted"

    def alert_context(self, event):
        return aws_rule_context(event)
