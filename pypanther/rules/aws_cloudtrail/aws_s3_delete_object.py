from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSS3DeleteObject(Rule):
    display_name = "AWS S3 Delete Object Detection"
    id = "AWS.S3.DeleteObject-prototype"
    threshold = 50
    default_severity = Severity.INFO
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "S3", "CloudTrail", "Beta"]
    default_description = "This rule detects when many objects are deleted from an S3 bucket. Such actions can be indicative of unauthorized data deletion or other suspicious activities.\n"
    default_runbook = "Investigate the user and the actions performed on the S3 bucket to ensure they were authorized. Unauthorized deletions can lead to data loss. Steps to investigate: 1. Identify the user who performed the action. 2. Verify if the action was authorized. 3. Check for any other suspicious activities performed by the same user. 4. If unauthorized, take necessary actions to secure the S3 bucket and prevent further unauthorized access.\n"
    default_reference = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/delete-objects.html"

    def rule(self, event):
        return (
            aws_cloudtrail_success(event)
            and event.get("eventSource") == "s3.amazonaws.com"
            and (event.get("eventName") == "DeleteObject")
        )

    def title(self, event):
        return f"[AWS.CloudTrail] User [{event.udm('actor_user')}] deleted many items from the [{event.deep_get('requestParameters', 'bucketName')}] bucket"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="DeleteObject",
            expected_result=True,
            log={
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "EXAMPLE",
                    "arn": "arn:aws:iam::123456789012:user/Alice",
                    "accountId": "123456789012",
                    "accessKeyId": "EXAMPLEKEY",
                    "userName": "Alice",
                },
                "eventTime": "2023-10-01T12:34:56Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "DeleteObject",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.0.2.0",
                "userAgent": "aws-sdk-go/1.15.12 (go1.12.6; linux; amd64)",
                "requestParameters": {"bucketName": "example-bucket", "key": "example-object"},
                "responseElements": None,
                "additionalEventData": {
                    "SignatureVersion": "SigV4",
                    "CipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "bytesTransferredIn": 0,
                    "bytesTransferredOut": 0,
                },
                "requestID": "EXAMPLE123456789",
                "eventID": "EXAMPLE-1234-5678-9012-EXAMPLE",
                "readOnly": False,
                "resources": [{"type": "AWS::S3::Object", "ARN": "arn:aws:s3:::example-bucket/example-object"}],
                "eventType": "AwsApiCall",
                "managementEvent": False,
                "recipientAccountId": "123456789012",
                "sharedEventID": "EXAMPLE-1234-5678-9012-EXAMPLE",
                "vpcEndpointId": "vpce-1a2b3c4d",
            },
        ),
        RuleTest(
            name="Other Event",
            expected_result=False,
            log={
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "EXAMPLE",
                    "arn": "arn:aws:iam::123456789012:user/Bob",
                    "accountId": "123456789012",
                    "accessKeyId": "EXAMPLEKEY",
                    "userName": "Bob",
                },
                "eventTime": "2023-10-01T12:34:56Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "ListBucket",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.0.2.0",
                "userAgent": "aws-sdk-go/1.15.12 (go1.12.6; linux; amd64)",
                "requestParameters": {"bucketName": "example-bucket"},
                "responseElements": None,
                "additionalEventData": {
                    "SignatureVersion": "SigV4",
                    "CipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "bytesTransferredIn": 0,
                    "bytesTransferredOut": 0,
                },
                "requestID": "EXAMPLE123456789",
                "eventID": "EXAMPLE-1234-5678-9012-EXAMPLE",
                "readOnly": True,
                "resources": [{"type": "AWS::S3::Bucket", "ARN": "arn:aws:s3:::example-bucket"}],
                "eventType": "AwsApiCall",
                "managementEvent": False,
                "recipientAccountId": "123456789012",
                "sharedEventID": "EXAMPLE-1234-5678-9012-EXAMPLE",
                "vpcEndpointId": "vpce-1a2b3c4d",
            },
        ),
    ]
