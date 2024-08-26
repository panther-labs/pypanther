from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context
from pypanther.helpers.panther_default import aws_cloudtrail_success

awskms_customer_managed_key_loss_tests: list[RuleTest] = [
    RuleTest(
        name="KMS Key Disabled",
        expected_result=True,
        log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
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
                },
            ],
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    RuleTest(
        name="KMS Key Scheduled For Deletion",
        expected_result=True,
        log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
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
            "requestParameters": {"keyId": "1", "pendingWindowInDays": 30, "overridePendingWindowCheck": False},
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
                },
            ],
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    RuleTest(
        name="KMS Key Non Deletion Event",
        expected_result=False,
        log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "attributes": {"mfaAuthenticated": "false", "creationDate": "2019-01-01T00:00:00Z"},
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
                    "aws:lambda:FunctionArn": "arn:aws:lambda:us-west-2:123456789012:function:function",
                },
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
                },
            ],
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    RuleTest(
        name="KMS Key Scheduled For Deletion - missing resources",
        expected_result=True,
        log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
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
            "requestParameters": {"keyId": "1", "pendingWindowInDays": 30, "overridePendingWindowCheck": False},
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
    RuleTest(
        name="KMS Disable Key Error",
        expected_result=False,
        log={
            "eventVersion": "1.05",
            "errorCode": "NotFoundException",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
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
                },
            ],
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
]


@panther_managed
class AWSKMSCustomerManagedKeyLoss(Rule):
    id = "AWS.KMS.CustomerManagedKeyLoss-prototype"
    display_name = "KMS CMK Disabled or Deleted"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Identity & Access Management", "Impact:Data Destruction"]
    reports = {"CIS": ["3.7"], "MITRE ATT&CK": ["TA0040:T1485"]}
    default_severity = Severity.INFO
    default_description = "A KMS Customer Managed Key was disabled or scheduled for deletion. This could potentially lead to permanent loss of encrypted data.\n"
    default_runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-kms-cmk-loss"
    default_reference = "https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html"
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    tests = awskms_customer_managed_key_loss_tests
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
