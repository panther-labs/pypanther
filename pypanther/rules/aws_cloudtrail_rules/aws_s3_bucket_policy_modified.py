from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.helpers.panther_default import aws_cloudtrail_success
from pypanther.log_types import LogType

awss3_bucket_policy_modified_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="S3 Bucket Policy Modified",
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
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutBucketAcl",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla",
            "requestParameters": {
                "host": ["bucket.s3.us-west-2.amazonaws.com"],
                "bucketName": "bucket",
                "acl": [""],
                "x-amz-acl": ["private"],
            },
            "responseElements": None,
            "additionalEventData": {
                "SignatureVersion": "SigV4",
                "CipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                "AuthenticationMethod": "AuthHeader",
            },
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    PantherRuleTest(
        Name="S3 Bucket Policy Modified Error Response",
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
            "eventSource": "s3.amazonaws.com",
            "errorCode": "AccessDenied",
            "eventName": "PutBucketAcl",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla",
            "requestParameters": {
                "host": ["bucket.s3.us-west-2.amazonaws.com"],
                "bucketName": "bucket",
                "acl": [""],
                "x-amz-acl": ["private"],
            },
            "responseElements": None,
            "additionalEventData": {
                "SignatureVersion": "SigV4",
                "CipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                "AuthenticationMethod": "AuthHeader",
            },
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    PantherRuleTest(
        Name="S3 Bucket Policy Not Modified",
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
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetBucketPolicy",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla",
            "requestParameters": {
                "host": ["bucket.s3.us-west-2.amazonaws.com"],
                "bucketName": "bucket",
                "policy": [""],
            },
            "responseElements": None,
            "additionalEventData": {
                "SignatureVersion": "SigV4",
                "CipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                "AuthenticationMethod": "AuthHeader",
            },
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
]


class AWSS3BucketPolicyModified(PantherRule):
    RuleID = "AWS.S3.BucketPolicyModified-prototype"
    DisplayName = "AWS S3 Bucket Policy Modified"
    LogTypes = [LogType.AWS_CloudTrail]
    Tags = ["AWS", "Identity & Access Management", "Exfiltration:Exfiltration Over Web Service"]
    Reports = {"CIS": ["3.8"], "MITRE ATT&CK": ["TA0010:T1567"]}
    Severity = PantherSeverity.Info
    DedupPeriodMinutes = 720
    Description = "An S3 Bucket was modified.\n"
    Runbook = (
        "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-s3-bucket-policy-modified"
    )
    Reference = "https://docs.aws.amazon.com/AmazonS3/latest/dev/using-iam-policies.html"
    SummaryAttributes = ["eventName", "userAgent", "sourceIpAddress", "p_any_aws_arns"]
    Tests = awss3_bucket_policy_modified_tests
    # API calls that are indicative of KMS CMK Deletion
    S3_POLICY_CHANGE_EVENTS = {
        "PutBucketAcl",
        "PutBucketPolicy",
        "PutBucketCors",
        "PutBucketLifecycle",
        "PutBucketReplication",
        "DeleteBucketPolicy",
        "DeleteBucketCors",
        "DeleteBucketLifecycle",
        "DeleteBucketReplication",
    }

    def rule(self, event):
        return event.get("eventName") in self.S3_POLICY_CHANGE_EVENTS and aws_cloudtrail_success(
            event
        )

    def title(self, event):
        return f"S3 bucket modified by [{deep_get(event, 'userIdentity', 'arn')}]"

    def alert_context(self, event):
        return aws_rule_context(event)
