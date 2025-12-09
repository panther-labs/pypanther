from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSS3CopyObjectToExternalAccountBucket(Rule):
    id = "AWS.S3.CopyObjectToExternalAccountBucket-prototype"
    display_name = "AWS S3 Object Copied to External Account Bucket"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Exfiltration:Transfer Data to Cloud Account", "Impact:Data Encrypted for Impact"]
    reports = {"MITRE ATT&CK": ["TA0010:T1537", "TA0040:T1486"]}
    default_severity = Severity.MEDIUM
    status = "Experimental"
    default_description = "Detects when an S3 object is copied from one bucket to another bucket in a different AWS account. This could indicate data exfiltration or a ransomware attack where data is copied to an attacker-controlled account.\n"
    default_runbook = "1. Query CloudTrail for all S3 API calls by the userIdentity:arn in the 24 hours before and after the alert to establish normal data access patterns\n2. Check if the destination account ID appears in any legitimate cross-account S3 operations in the past 90 days\n3. Find all CopyObject events to the same destination bucket from any user in the past 7 days to identify if this is part of a broader exfiltration campaign\n"
    default_reference = "https://www.trendmicro.com/en_us/research/25/k/s3-ransomware.html"
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]

    def extract_resources(self, event):
        resources = event.get("resources", [])
        bucket_accounts = {}
        if len(resources) > 0:
            for resource in resources:
                if resource.get("type") == "AWS::S3::Bucket":
                    bucket_name = resource.get("arn", "").split(":::")[-1]
                    account_id = resource.get("accountId", "")
                    bucket_accounts[bucket_name] = account_id
        return bucket_accounts

    def rule(self, event):
        if event.get("eventName") != "CopyObject" or not aws_cloudtrail_success(event):
            return False
        bucket_accounts = self.extract_resources(event)
        # Need at least 2 buckets to compare accounts
        if len(bucket_accounts) < 2:
            return False
        # Check if buckets belong to different accounts
        account_ids = set(bucket_accounts.values())
        if len(account_ids) > 1:
            return True
        return False

    def title(self, event):
        dest_bucket = event.deep_get("requestParameters", "bucketName", default="<UNKNOWN_DESTINATION_BUCKET>")
        source_bucket = event.deep_get("requestParameters", "x-amz-copy-source", default="<UNKNOWN_SOURCE_BUCKET>")
        actor = event.udm("actor_user")
        return f"[AWS.CloudTrail] User [{actor}] copied objects to external AWS account bucket [{dest_bucket}] from bucket [{source_bucket}]"

    def alert_context(self, event):
        context = aws_rule_context(event)
        context["bucket_accounts"] = self.extract_resources(event)
        context["dest_bucket"] = event.deep_get(
            "requestParameters",
            "bucketName",
            default="<UNKNOWN_DESTINATION_BUCKET>",
        )
        # Extract just the bucket name from x-amz-copy-source (format: bucket/key)
        source_path = event.deep_get("requestParameters", "x-amz-copy-source", default="<UNKNOWN_SOURCE_BUCKET>")
        context["bucketName"] = source_path.split("/")[0] if "/" in source_path else source_path
        return context

    tests = [
        RuleTest(
            name="S3 CopyObject to External Account Bucket",
            expected_result=True,
            log={
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "AIDAI1234567890EXAMPLE:user",
                    "arn": "arn:aws:sts::12948575929274:assumed-role/sample-role-keen-cohen/sample-role-hardcore-driscoll-role-brave-yalow-role-intelligent-brahmagupta-role-admiring-vaughan-role-sad-khayyam-role-eager-haslett",
                    "accountId": "12948575929274",
                    "accessKeyId": "AKIA-MOCKACCESSKEYID-1",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "false", "creationDate": "2024-01-15T10:30:00Z"},
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "AIDAI1234567890EXAMPLE",
                            "arn": "arn:aws:iam::12948575929274:role/sample-role-keen-cohen",
                            "accountId": "12948575929274",
                            "userName": "AdminRole",
                        },
                    },
                },
                "eventTime": "2024-01-15T12:00:00Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "CopyObject",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "aws-cli/2.13.0",
                "requestParameters": {
                    "bucketName": "attacker-exfil-1764604156",
                    "key": "customer-database.csv",
                    "x-amz-copy-source": "ransomware-test-victim-1764604156/customer-database.csv",
                },
                "responseElements": None,
                "requestID": "ABC123DEF456",
                "eventID": "12345678-1234-1234-1234-222222222222",
                "eventType": "AwsApiCall",
                "recipientAccountId": "12948575929274",
                "resources": [
                    {
                        "accountId": "111111111111",
                        "arn": "arn:aws:s3:::sample-bucket-magical-ardinghelli",
                        "type": "AWS::S3::Bucket",
                    },
                    {
                        "arn": "arn:aws:s3:::sample-bucket-magical-ardinghelli/customer-database.csv",
                        "type": "AWS::S3::Object",
                    },
                    {
                        "accountId": "12948575929274",
                        "arn": "arn:aws:s3:::sample-bucket-busy-carver",
                        "type": "AWS::S3::Bucket",
                    },
                    {"arn": "arn:aws:s3:::sample-bucket-busy-carver/customer-database.csv", "type": "AWS::S3::Object"},
                ],
            },
        ),
        RuleTest(
            name="S3 CopyObject Same Account",
            expected_result=False,
            log={
                "eventVersion": "1.09",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "AIDAI1234567890EXAMPLE:user",
                    "arn": "arn:aws:sts::12948575929274:assumed-role/AdminRole/user",
                    "accountId": "12948575929274",
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                },
                "eventTime": "2024-01-15T12:00:00Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "CopyObject",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.42",
                "userAgent": "aws-cli/2.13.0",
                "requestParameters": {
                    "bucketName": "my-source-bucket",
                    "key": "data.csv",
                    "x-amz-copy-source": "my-source-bucket/data.csv",
                },
                "responseElements": None,
                "requestID": "ABC123DEF456",
                "eventID": "12345678-1234-1234-1234-123456789012",
                "eventType": "AwsApiCall",
                "recipientAccountId": "12948575929274",
                "resources": [
                    {"accountId": "12948575929274", "arn": "arn:aws:s3:::my-source-bucket", "type": "AWS::S3::Bucket"},
                    {"arn": "arn:aws:s3:::my-source-bucket/data.csv", "type": "AWS::S3::Object"},
                    {"accountId": "12948575929274", "arn": "arn:aws:s3:::my-dest-bucket", "type": "AWS::S3::Bucket"},
                    {"arn": "arn:aws:s3:::my-dest-bucket/data.csv", "type": "AWS::S3::Object"},
                ],
            },
        ),
    ]
