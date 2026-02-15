import re

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSS3RansomwareNoteUpload(Rule):
    display_name = "AWS S3 Ransomware Note Upload Detection"
    id = "AWS.S3.RansomwareNoteUpload-prototype"
    default_severity = Severity.MEDIUM
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "S3", "CloudTrail", "Ransomware", "DataSecurity"]
    status = "Experimental"
    default_description = "This rule detects when files with names commonly associated with ransomware notes are uploaded to S3 buckets. Ransomware attackers often drop ransom notes with distinctive filenames like HOW_TO_DECRYPT_FILES.txt, RANSOM_NOTE.txt, FILES_ENCRYPTED.html, or similar patterns to inform victims about the encryption and provide payment instructions.\n"
    default_runbook = "1. Query CloudTrail for all S3 API calls by the userIdentity:arn in the 24 hours before and after this alert, focusing on DeleteObject, DeleteObjects, PutBucketEncryption, DeleteBucketEncryption, and PutBucketVersioning events from the same requestParameters:bucketName\n2. Check if the sourceIPAddress has accessed this S3 bucket in the past 90 days and compare the volume of operations to establish if this is anomalous activity\n3. Find other alerts with this rule ID or any S3 deletion/encryption rules for the same bucket or user in the past 7 days to identify if this is part of a coordinated ransomware attack pattern\n"
    default_reference = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-content-structure.html"
    # Common ransomware note filename patterns
    # Explicit ransomware-related terms
    # RANSOM_NOTE.txt, PAYMENT_INFO.html
    # Decrypt/restore with specific action words
    # HOW_TO_DECRYPT_FILES.txt
    # DECRYPT_INSTRUCTIONS.txt
    # RESTORE_INSTRUCTIONS.txt
    # RECOVERY_INSTRUCTIONS.txt
    # Files encrypted/locked messages
    # FILES_ENCRYPTED.txt, ALL_FILES_HAVE_BEEN_ENCRYPTED.txt
    # YOUR_FILES_ARE_ENCRYPTED.txt
    # DATA_ENCRYPTED.txt
    # Unlock-related (common in ransomware)
    # UNLOCK_INSTRUCTIONS.txt
    # Help decrypt/restore (specific to ransomware)
    # HELP_DECRYPT_YOUR_FILES.txt
    RANSOM_NOTE_PATTERNS = [
        "(?i)(ransom|payment)[_-]?(note|info|instructions?).*\\.(txt|html?)$",
        "(?i)how[_-]?to[_-]?(decrypt|restore|recover)[_-]?(your[_-]?)?files.*\\.(txt|html?)$",
        "(?i)decrypt[_-]?(instructions?|guide|info|your[_-]?files).*\\.(txt|html?)$",
        "(?i)restore[_-]?(instructions?|guide|info|your[_-]?files).*\\.(txt|html?)$",
        "(?i)recovery[_-]?(instructions?|key|guide).*\\.(txt|html?)$",
        "(?i)(all[_-]?)?files?[_-]?(have[_-]?been[_-]?)?(encrypted|locked).*\\.(txt|html?)$",
        "(?i)your[_-]?files?[_-]?(are|have[_-]?been)[_-]?(encrypted|locked).*\\.(txt|html?)$",
        "(?i)data[_-]?(has[_-]?been[_-]?)?(encrypted|locked).*\\.(txt|html?)$",
        "(?i)unlock[_-]?(instructions?|guide|your[_-]?files).*\\.(txt|html?)$",
        "(?i)help[_-]?(restore|decrypt|recover)[_-]?(your[_-]?)?files.*\\.(txt|html?)$",
    ]
    COMPILED_PATTERNS = [re.compile(pattern) for pattern in RANSOM_NOTE_PATTERNS]

    def extract_filename(self, event):
        key = event.deep_get("requestParameters", "key", default="")
        if not key:
            resources = event.get("resources", [])
            for resource in resources:
                if resource.get("type") == "AWS::S3::Object":
                    arn = resource.get("arn", "")
                    # Extract key from ARN (format: arn:aws:s3:::bucket/key)
                    if "/" in arn:
                        key = arn.split("/", 1)[1]
                        break
        filename = key.split("/")[-1] if "/" in key else key
        return filename

    def rule(self, event):
        if event.get("eventName") != "PutObject" or not aws_cloudtrail_success(event):
            return False
        filename = self.extract_filename(event)
        # Check if filename matches any ransomware note pattern
        return any(pattern.match(filename) for pattern in self.COMPILED_PATTERNS)

    def title(self, event):
        bucket = event.deep_get("requestParameters", "bucketName", default="<UNKNOWN_BUCKET>")
        filename = self.extract_filename(event)
        return f"[AWS.CloudTrail] Potential ransomware note uploaded to S3: [{filename}] in bucket [{bucket}] by user [{event.udm('actor_user')}]"

    def alert_context(self, event):
        context = aws_rule_context(event)
        key = event.deep_get("requestParameters", "key", default="<UNKNOWN_KEY>")
        context["bucketName"] = event.deep_get("requestParameters", "bucketName", default="<UNKNOWN_BUCKET>")
        context["objectKey"] = key
        context["filename"] = self.extract_filename(event)
        return context

    tests = [
        RuleTest(
            name="Ransomware Note - HOW_TO_DECRYPT_FILES.txt",
            expected_result=True,
            log={
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AIDA-MOCKIAMUSERID-1",
                    "arn": "arn:aws:iam::111111111111:user/compromised-user",
                    "accountId": "111111111111",
                    "accessKeyId": "AKIA-MOCKACCESSKEYID-1",
                    "userName": "compromised-user",
                },
                "eventTime": "2025-12-03T18:00:00Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutObject",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "aws-sdk-python/1.26.0",
                "requestParameters": {
                    "bucketName": "production-data",
                    "key": "documents/financial/HOW_TO_DECRYPT_FILES.txt",
                    "Host": "sample-bucket-hungry-buck.s3.us-west-2.amazonaws.com",
                },
                "responseElements": None,
                "additionalEventData": {
                    "SignatureVersion": "SigV4",
                    "CipherSuite": "TLS_AES_128_GCM_SHA256",
                    "bytesTransferredIn": 2048,
                    "bytesTransferredOut": 0,
                    "SSEApplied": "SSE_S3",
                },
                "requestID": "EXAMPLE987654321",
                "eventID": "z9y8x7w6-5432-10fe-dcba-EXAMPLE22222",
                "readOnly": False,
                "resources": [
                    {
                        "type": "AWS::S3::Bucket",
                        "ARN": "arn:aws:s3:::sample-bucket-hungry-buck",
                        "accountId": "111111111111",
                    },
                    {
                        "type": "AWS::S3::Object",
                        "ARN": "arn:aws:s3:::sample-bucket-hungry-buck/documents/financial/HOW_TO_DECRYPT_FILES.txt",
                    },
                ],
                "eventType": "AwsApiCall",
                "managementEvent": False,
                "recipientAccountId": "111111111111",
            },
        ),
        RuleTest(
            name="Normal File Upload - quarterly_report.pdf",
            expected_result=False,
            log={
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AIDAI23HXE2NYPEXAMPLE",
                    "arn": "arn:aws:iam::123456789012:user/legitimate-user",
                    "accountId": "123456789012",
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "userName": "legitimate-user",
                },
                "eventTime": "2025-12-03T18:00:00Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutObject",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.10",
                "userAgent": "aws-cli/2.13.0",
                "requestParameters": {
                    "bucketName": "my-company-bucket",
                    "key": "reports/quarterly-report.pdf",
                    "Host": "my-company-bucket.s3.us-east-1.amazonaws.com",
                },
                "responseElements": {"x-amz-server-side-encryption": "AES256"},
                "additionalEventData": {
                    "SignatureVersion": "SigV4",
                    "CipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "bytesTransferredIn": 524288,
                    "bytesTransferredOut": 0,
                },
                "requestID": "EXAMPLE555666777",
                "eventID": "b1b2b3b4-4444-5555-6666-EXAMPLE55555",
                "readOnly": False,
                "resources": [
                    {"type": "AWS::S3::Bucket", "ARN": "arn:aws:s3:::my-company-bucket", "accountId": "123456789012"},
                    {"type": "AWS::S3::Object", "ARN": "arn:aws:s3:::my-company-bucket/reports/quarterly-report.pdf"},
                ],
                "eventType": "AwsApiCall",
                "managementEvent": False,
                "recipientAccountId": "123456789012",
            },
        ),
    ]
