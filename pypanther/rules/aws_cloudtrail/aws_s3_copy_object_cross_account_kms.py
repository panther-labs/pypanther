from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSS3CopyObjectCrossAccountEncryptionKMS(Rule):
    id = "AWS.S3.CopyObject.CrossAccount.Encryption.KMS-prototype"
    display_name = "S3 Object Encrypted with External KMS Key"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "S3", "Ransomware", "Impact:Data Destruction"]
    reports = {"MITRE ATT&CK": ["TA0040:T1486"]}
    default_severity = Severity.HIGH
    status = "Experimental"
    default_description = "Detects when an S3 object is copied with a KMS key belonging to an account ID different than the bucket owner's account ID. This technique is used in S3 ransomware attacks where attackers encrypt objects with their own KMS key from an attacker-controlled AWS account, making the data inaccessible to the original owner. This is often a precursor to ransom demands or permanent data loss.\n"
    default_runbook = "1. Query CloudTrail for all CopyObject events by the userIdentity:arn in the 24 hours before and after the alert to identify all affected objects in the requestParameters:bucketName\n2. Check if the KMS key ARN from resources field belongs to an external account ID that appears in any legitimate cross-account operations in the past 90 days\n3. Find all S3 GetObject and ListBucket events by this user on the source bucket in the 1 hour before the first CopyObject to check if the attacker performed reconnaissance\n"
    default_reference = "https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/"

    def rule(self, event):
        if event.get("eventName") != "CopyObject" or not aws_cloudtrail_success(event):
            return False
        kms_key_arn = event.deep_get(
            "requestParameters",
            "x-amz-server-side-encryption-aws-kms-key-id",
            default="<UNKNOWN_KEY_ID>",
        )
        if kms_key_arn.startswith("arn:aws:kms:"):
            # Extract account ID from KMS key ARN (format: arn:aws:kms:region:account:key/key-id)
            kms_parts = kms_key_arn.split(":")
            if len(kms_parts) >= 5:
                kms_account_id = kms_parts[4]
                bucket_account_id = event.get("recipientAccountId", "")
                # Alert on cross-account KMS key usage
                if kms_account_id != bucket_account_id:
                    return True
        return False

    def title(self, event):
        return f"[AWS.CloudTrail] User [{event.udm('actor_user')}] encrypted an object in bucket [{event.deep_get('requestParameters', 'bucketName')}] with a KMS key belonging to a different account ID than the account owner ID"

    def alert_context(self, event):
        context = aws_rule_context(event)
        context["bucketName"] = event.deep_get("requestParameters", "bucketName", default="<UNKNOWN_BUCKET>")
        context["objectKey"] = event.deep_get("requestParameters", "key", default="<UNKNOWN_KEY>")
        kms_key_arn = event.deep_get(
            "requestParameters",
            "x-amz-server-side-encryption-aws-kms-key-id",
            default="<UNKNOWN_KEY_ARN>",
        )
        context["kmsKeyId"] = kms_key_arn
        # Add cross-account indicator
        if kms_key_arn:
            kms_parts = kms_key_arn.split(":")
            if len(kms_parts) >= 5:
                kms_account_id = kms_parts[4]
                bucket_account_id = event.get("recipientAccountId", "")
                context["isCrossAccountKms"] = kms_account_id != bucket_account_id
                context["kmsAccountId"] = kms_account_id
                context["bucketAccountId"] = bucket_account_id
        context["encryption"] = event.deep_get(
            "requestParameters",
            "x-amz-server-side-encryption",
            default="<UNKNOWN_ENCRYPTION>",
        )
        return context

    tests = [
        RuleTest(
            name="In-Place Copy with KMS Key Change",
            expected_result=True,
            log={
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "AAAAAAAAAAAAAAAAAAAAA:attacker",
                    "arn": "arn:aws:sts::111111111111:assumed-role/sample-role-elastic-rhodes/sample-role-brave-yalow-role-jolly-banzai-role-intelligent-brahmagupta-role-admiring-cori-role-beautiful-keldysh-role-hopeful-chaplygin",
                    "accountId": "111111111111",
                    "accessKeyId": "ASIA-MOCKACCESSKEYID-1",
                },
                "eventTime": "2024-01-15T10:45:23Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "CopyObject",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "aws-cli/2.13.0 Python/3.11.4",
                "requestParameters": {
                    "bucketName": "victim-data-bucket",
                    "key": "important-file.txt",
                    "x-amz-copy-source": "victim-data-bucket/important-file.txt",
                    "x-amz-server-side-encryption": "aws:kms",
                    "x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:999999999999:key/attacker-key-id",
                },
                "responseElements": None,
                "requestID": "ABC123DEF456",
                "eventID": "12345678-1234-1234-1234-111111111111",
                "readOnly": False,
                "resources": [
                    {"type": "AWS::S3::Object", "ARN": "arn:aws:s3:::sample-bucket-quizzical-yalow/important-file.txt"},
                    {
                        "accountId": "999999999999",
                        "type": "AWS::KMS::Key",
                        "ARN": "arn:aws:kms:us-east-1:999999999999:key/attacker-key-id",
                    },
                ],
                "eventType": "AwsApiCall",
                "managementEvent": False,
                "recipientAccountId": "111111111111",
            },
        ),
        RuleTest(
            name="Copy with Same Account Owner",
            expected_result=False,
            log={
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "AAAAAAAAAAAAAAAAAAAAA:attacker",
                    "arn": "arn:aws:sts::111111111111:assumed-role/sample-role-elastic-rhodes/sample-role-beautiful-keldysh-role-hopeful-chaplygin",
                    "accountId": "111111111111",
                    "accessKeyId": "ASIA-MOCKACCESSKEYID-1",
                },
                "eventTime": "2024-01-15T10:45:23Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "CopyObject",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "aws-cli/2.13.0 Python/3.11.4",
                "requestParameters": {
                    "bucketName": "victim-data-bucket",
                    "key": "important-file.txt",
                    "x-amz-copy-source": "victim-data-bucket/important-file.txt",
                    "x-amz-server-side-encryption": "aws:kms",
                    "x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:111111111111:key/developer",
                },
                "responseElements": None,
                "requestID": "ABC123DEF456",
                "eventID": "12345678-1234-1234-1234-111111111111",
                "readOnly": False,
                "resources": [
                    {"type": "AWS::S3::Object", "ARN": "arn:aws:s3:::sample-bucket-quizzical-yalow/important-file.txt"},
                    {
                        "accountId": "111111111111",
                        "type": "AWS::KMS::Key",
                        "ARN": "arn:aws:kms:us-east-1:111111111111:key/attacker-key-id",
                    },
                ],
                "eventType": "AwsApiCall",
                "managementEvent": False,
                "recipientAccountId": "111111111111",
            },
        ),
    ]
