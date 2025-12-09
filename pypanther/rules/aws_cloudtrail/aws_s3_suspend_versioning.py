from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSS3SuspendVersioning(Rule):
    id = "AWS.S3.SuspendVersioning-prototype"
    display_name = "S3 Bucket Versioning Suspended"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Defense Evasion", "Impact:Data Destruction"]
    reports = {"MITRE ATT&CK": ["TA0005:T1562", "TA0040:T1485"]}
    default_severity = Severity.LOW
    status = "Experimental"
    default_description = "Detects when S3 bucket versioning is suspended or disabled, which removes the ability to recover previous versions of objects and is a common precursor to ransomware attacks or data destruction."
    default_runbook = "1. Query CloudTrail for all S3 API calls by the userIdentity:arn on the requestParameters:bucketName in the 24 hours before and after versioning was suspended\n2. Find any DeleteObject or DeleteObjects events on this bucket in the 6 hours after versioning was suspended to detect potential data destruction attempts\n3. Search for other security control changes (DisableBucketLogging, DisableMfaDelete, DeleteBucketEncryption) on the same bucket in the past 7 days to identify coordinated attack patterns\n"
    default_reference = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"
    summary_attributes = ["sourceIpAddress", "userAgent", "recipientAccountId", "p_any_aws_arns"]

    def rule(self, event):
        return (
            aws_cloudtrail_success(event)
            and event.get("eventSource") == "s3.amazonaws.com"
            and (event.get("eventName") == "PutBucketVersioning")
            and (event.deep_get("requestParameters", "VersioningConfiguration", "Status") in ("Suspended", "Disabled"))
        )

    def title(self, event):
        return f"[AWS.CloudTrail] User [{event.udm('actor_user')}] suspended object versioning in bucket [{event.deep_get('requestParameters', 'bucketName')}]"

    def alert_context(self, event):
        context = aws_rule_context(event)
        context["bucketName"] = event.deep_get("requestParameters", "bucketName", default="UNKNOWN_BUCKET")
        return context

    tests = [
        RuleTest(
            name="Versioning Suspended Successfully",
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
                "eventName": "PutBucketVersioning",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.10.0-1234-aws exe/x86_64.ubuntu.22",
                "requestParameters": {
                    "bucketName": "important-files-bucket",
                    "host": "sample-bucket-lucid-jang.s3.amazonaws.com",
                    "VersioningConfiguration": {"Status": "Suspended"},
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
            name="Versioning Disabled Successfully",
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
                "eventName": "PutBucketVersioning",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.10.0-1234-aws exe/x86_64.ubuntu.22",
                "requestParameters": {
                    "bucketName": "important-files-bucket",
                    "host": "sample-bucket-lucid-jang.s3.amazonaws.com",
                    "VersioningConfiguration": {"Status": "Disabled"},
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
            name="Versioning Change Failed",
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
                "eventName": "PutBucketVersioning",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.10.0-1234-aws exe/x86_64.ubuntu.22",
                "errorCode": "AccessDenied",
                "errorMessage": "Access Denied",
                "requestParameters": {
                    "bucketName": "important-files-bucket",
                    "host": "sample-bucket-lucid-jang.s3.amazonaws.com",
                    "VersioningConfiguration": {"Status": "Suspended"},
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
            name="Versioning Enabled",
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
                "eventName": "PutBucketVersioning",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.10.0-1234-aws exe/x86_64.ubuntu.22",
                "requestParameters": {
                    "bucketName": "important-files-bucket",
                    "host": "sample-bucket-lucid-jang.s3.amazonaws.com",
                    "VersioningConfiguration": {"Status": "Enabled"},
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
                "eventName": "DeleteBucketEncryption",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.10.0-1234-aws exe/x86_64.ubuntu.22",
                "requestParameters": {
                    "bucketName": "important-files-bucket",
                    "host": "sample-bucket-lucid-jang.s3.amazonaws.com",
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
                "eventName": "PutBucketVersioning",
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
