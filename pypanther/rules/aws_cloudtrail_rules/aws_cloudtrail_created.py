from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.helpers.panther_default import aws_cloudtrail_success
from pypanther.log_types import LogType

aws_cloud_trail_created_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="CloudTrail Was Created",
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
            "eventName": "CreateTrail",
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
        Name="KMS Decrypt Event",
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
            "eventSource": "kms.amazonaws.com",
            "eventName": "Decrypt",
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
        Name="Error Creating CloudTrail",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.05",
            "errorCode": "CloudTrailInvalidClientTokenIdException",
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
            "eventName": "CreateTrail",
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


class AWSCloudTrailCreated(PantherRule):
    RuleID = "AWS.CloudTrail.Created-prototype"
    DisplayName = "A CloudTrail Was Created or Updated"
    LogTypes = [LogType.AWS_CloudTrail]
    Tags = ["AWS", "Security Control", "Discovery:Cloud Service Dashboard"]
    Reports = {"CIS": ["3.5"], "MITRE ATT&CK": ["TA0007:T1538"]}
    Severity = PantherSeverity.Info
    Description = "A CloudTrail Trail was created, updated, or enabled.\n"
    Runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-cloudtrail-modified"
    Reference = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html"
    SummaryAttributes = [
        "eventName",
        "userAgent",
        "sourceIpAddress",
        "recipientAccountId",
        "p_any_aws_arns",
    ]
    Tests = aws_cloud_trail_created_tests
    # API calls that are indicative of CloudTrail changes
    CLOUDTRAIL_CREATE_UPDATE = {"CreateTrail", "UpdateTrail", "StartLogging"}

    def rule(self, event):
        return (
            aws_cloudtrail_success(event)
            and event.get("eventName") in self.CLOUDTRAIL_CREATE_UPDATE
        )

    def title(self, event):
        return f"CloudTrail [{deep_get(event, 'requestParameters', 'name')}] was created/updated"

    def alert_context(self, event):
        return aws_rule_context(event)
