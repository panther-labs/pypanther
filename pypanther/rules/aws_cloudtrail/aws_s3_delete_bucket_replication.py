from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSS3DeleteBucketReplication(Rule):
    id = "AWS.S3.DeleteBucketReplication-prototype"
    display_name = "S3 Bucket Replication Deleted"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Defense Evasion", "Impact:Data Destruction"]
    reports = {"MITRE ATT&CK": ["TA0005:T1562", "TA0040:T1485"]}
    default_severity = Severity.MEDIUM
    status = "Experimental"
    default_description = "Detects when S3 bucket replication configuration is deleted, which could prevent data backup and indicate ransomware preparation activity."
    default_runbook = "1. Query CloudTrail for all S3 API calls by the userIdentity:arn on the requestParameters:bucketName in the 24 hours before and after the replication deletion to establish full activity context\n2. Check if this user has historically managed replication settings for this bucket in the past 90 days to verify if this is authorized administrative work\n3. Find other alerts indicating security control disabling (DeleteBucketEncryption, SuspendVersioning, DisableBucketLogging) for the same bucket in the past 7 days to identify ransomware preparation patterns\n"
    default_reference = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html"
    summary_attributes = ["sourceIpAddress", "userAgent", "recipientAccountId", "p_any_aws_arns"]

    def rule(self, event):
        return (
            aws_cloudtrail_success(event)
            and event.get("eventSource") == "s3.amazonaws.com"
            and (event.get("eventName") == "DeleteBucketReplication")
        )

    def title(self, event):
        return f"[AWS.CloudTrail] User [{event.udm('actor_user')}] deleted bucket replication for bucket [{event.deep_get('requestParameters', 'bucketName')}] bucket"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Bucket Replication Deleted Successfully",
            expected_result=True,
            log={
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "AAAAAAAAAAAAAAAAAAAAA:user_name",
                    "arn": "arn:aws:sts::111111111111:assumed-role/sample-role-dreamy-yonath/sample-role-brave-yalow-role-intelligent-brahmagupta-role-beautiful-keldysh-role-happy-easley-role-bold-buck",
                    "accountId": "111111111111",
                    "accessKeyId": "ASIA-MOCKACCESSKEYID-1",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "false", "creationDate": "2024-01-15T10:30:00Z"},
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "AAAAAAAAAAAAAAAAAAAAA",
                            "arn": "arn:aws:iam::111111111111:role/sample-role-dreamy-yonath",
                            "accountId": "111111111111",
                            "userName": "AdminRole",
                        },
                    },
                },
                "eventTime": "2024-01-15T10:45:23Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "DeleteBucketReplication",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.10.0-1234-aws exe/x86_64.ubuntu.22",
                "requestParameters": {
                    "bucketName": "production-backup-bucket",
                    "host": "sample-bucket-serene-pike.s3.amazonaws.com",
                    "replication": "",
                },
                "responseElements": None,
                "requestID": "ABC123DEF456",
                "eventID": "12345678-1234-1234-1234-111111111111",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "managementEvent": True,
                "recipientAccountId": "111111111111",
                "vpcEndpointId": "vpce-1a2b3c4d",
            },
        ),
        RuleTest(
            name="Bucket Replication Deletion Failed",
            expected_result=False,
            log={
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AIDAI23HXS4EXAMPLE",
                    "arn": "arn:aws:iam::111111111111:user/testuser",
                    "accountId": "111111111111",
                    "accessKeyId": "AKIA-MOCKACCESSKEYID-1",
                },
                "eventTime": "2024-01-15T10:45:23Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "DeleteBucketReplication",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.10.0-1234-aws exe/x86_64.ubuntu.22",
                "errorCode": "AccessDenied",
                "errorMessage": "Access Denied",
                "requestParameters": {
                    "bucketName": "production-backup-bucket",
                    "host": "sample-bucket-serene-pike.s3.amazonaws.com",
                },
                "responseElements": None,
                "requestID": "ABC123DEF456",
                "eventID": "12345678-1234-1234-1234-111111111111",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "managementEvent": True,
                "recipientAccountId": "111111111111",
            },
        ),
        RuleTest(
            name="Different S3 Event",
            expected_result=False,
            log={
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "AAAAAAAAAAAAAAAAAAAAA:user_name",
                    "arn": "arn:aws:sts::111111111111:assumed-role/sample-role-dreamy-yonath/sample-role-brave-yalow-role-intelligent-brahmagupta-role-beautiful-keldysh-role-happy-easley-role-bold-buck",
                    "accountId": "111111111111",
                    "accessKeyId": "ASIA-MOCKACCESSKEYID-1",
                },
                "eventTime": "2024-01-15T10:45:23Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutBucketReplication",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.10.0-1234-aws exe/x86_64.ubuntu.22",
                "requestParameters": {
                    "bucketName": "production-backup-bucket",
                    "host": "sample-bucket-serene-pike.s3.amazonaws.com",
                },
                "responseElements": None,
                "requestID": "ABC123DEF456",
                "eventID": "12345678-1234-1234-1234-111111111111",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "managementEvent": True,
                "recipientAccountId": "111111111111",
            },
        ),
        RuleTest(
            name="Non-S3 Event",
            expected_result=False,
            log={
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "AAAAAAAAAAAAAAAAAAAAA:user_name",
                    "arn": "arn:aws:sts::123456789012:assumed-role/AdminRole/user_name",
                    "accountId": "123456789012",
                    "accessKeyId": "ASIAIOSFODNN7EXAMPLE",
                },
                "eventTime": "2024-01-15T10:45:23Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "DeleteBucketReplication",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.42",
                "userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.10.0-1234-aws exe/x86_64.ubuntu.22",
                "requestParameters": {},
                "responseElements": None,
                "requestID": "ABC123DEF456",
                "eventID": "12345678-1234-1234-1234-123456789012",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "managementEvent": True,
                "recipientAccountId": "123456789012",
            },
        ),
    ]
