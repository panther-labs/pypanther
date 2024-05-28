from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context
from pypanther.helpers.panther_default import aws_cloudtrail_success
from pypanther.log_types import LogType

awskms_customer_managed_key_loss_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="KMS Key Disabled",
        ExpectedResult=True,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true",
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
            "eventName": "DisableKey",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla",
            "requestParameters": {"keyId": "1"},
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "readOnly": False,
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
        Name="KMS Key Scheduled For Deletion",
        ExpectedResult=True,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true",
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
            "eventName": "ScheduleKeyDeletion",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla",
            "requestParameters": {
                "keyId": "1",
                "pendingWindowInDays": 30,
                "overridePendingWindowCheck": False,
            },
            "responseElements": {
                "keyId": "arn:aws:kms:us-west-2:123456789012:key/1",
                "deletionDate": "Jan 1, 2019 12:00:00 AM",
            },
            "requestID": "1",
            "eventID": "1",
            "readOnly": False,
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
        Name="KMS Key Non Deletion Event",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
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
                    "aws:lambda:FunctionArn": "arn:aws:lambda:us-west-2:123456789012:function:function"
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
        Name="KMS Key Scheduled For Deletion - missing resources",
        ExpectedResult=True,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true",
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
            "eventName": "ScheduleKeyDeletion",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla",
            "requestParameters": {
                "keyId": "1",
                "pendingWindowInDays": 30,
                "overridePendingWindowCheck": False,
            },
            "responseElements": {
                "keyId": "arn:aws:kms:us-west-2:123456789012:key/1",
                "deletionDate": "Jan 1, 2019 12:00:00 AM",
            },
            "requestID": "1",
            "eventID": "1",
            "readOnly": False,
            "resources": None,
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
            "p_row_id": "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234",
        },
    ),
    PantherRuleTest(
        Name="KMS Disable Key Error",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.05",
            "errorCode": "NotFoundException",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true",
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
            "eventName": "DisableKey",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla",
            "requestParameters": {"keyId": "1"},
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "readOnly": False,
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
]


class AWSKMSCustomerManagedKeyLoss(PantherRule):
    RuleID = "AWS.KMS.CustomerManagedKeyLoss-prototype"
    DisplayName = "KMS CMK Disabled or Deleted"
    LogTypes = [LogType.AWS_CloudTrail]
    Tags = ["AWS", "Identity & Access Management", "Impact:Data Destruction"]
    Reports = {"CIS": ["3.7"], "MITRE ATT&CK": ["TA0040:T1485"]}
    Severity = PantherSeverity.Info
    Description = "A KMS Customer Managed Key was disabled or scheduled for deletion. This could potentially lead to permanent loss of encrypted data.\n"
    Runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-kms-cmk-loss"
    Reference = "https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html"
    SummaryAttributes = [
        "eventName",
        "userAgent",
        "sourceIpAddress",
        "recipientAccountId",
        "p_any_aws_arns",
    ]
    Tests = awskms_customer_managed_key_loss_tests
    # API calls that are indicative of KMS CMK Deletion
    KMS_LOSS_EVENTS = {"DisableKey", "ScheduleKeyDeletion"}
    KMS_KEY_TYPE = "AWS::KMS::Key"

    def rule(self, event):
        return aws_cloudtrail_success(event) and event.get("eventName") in self.KMS_LOSS_EVENTS

    def dedup(self, event):
        for resource in event.get("resources") or []:
            if resource.get("type", "") == self.KMS_KEY_TYPE:
                return resource.get("ARN")
        return event.get("eventName")

    def alert_context(self, event):
        return aws_rule_context(event)
