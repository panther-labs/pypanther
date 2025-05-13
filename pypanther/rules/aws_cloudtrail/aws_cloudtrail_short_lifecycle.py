from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context, lookup_aws_account_name
from pypanther.helpers.base import deep_get


@panther_managed
class AWSCloudTrailShortLifecycle(Rule):
    id = "AWS.CloudTrail.ShortLifecycle-prototype"
    display_name = "AWS CloudTrail Retention Lifecycle Too Short"
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.INFO
    reports = {"MITRE ATT&CK": ["TA0005:T1562.008"]}
    default_description = "Detects when an S3 bucket containing CloudTrail logs has been modified to delete data after a short period of time."
    default_reference = (
        "https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-lifecycle-rule/"
    )
    default_runbook = "Verify whether the bucket in question contains CloudTrail data, and if so, why the lifecycle was changed. Potentally add a filter for this bucket to prevent future false positives."
    tags = [
        "AWS",
        "Cloudtrail",
        "Defense Evasion",
        "Impair Defenses",
        "Disable or Modify Cloud Logs",
        "Defense Evasion:Impair Defenses",
        "Security Control",
        "Beta",
    ]
    # Use this to record the names of your S3 buckets that have cloudtrail logs
    #   If a bucket name isn't mentioned here, we still make a best guess as to whether or not it
    #   contains CloudTrail data, but the confidence rating will be lower, and so will the severity
    CLOUDTRAIL_BUCKETS = ("example_cloudtrail_bucket_name",)
    # This is the minimum length fo time CloudTrail logs should remain in an S3 bucket.
    #   We set this to 7 initially, since this is the recommended amount of time logs ingested by
    #   Panther should remain available. You can modify this if you wish.
    CLOUDTRAIL_MINIMUM_STORAGE_PERIOD_DAYS = 7

    def rule(self, event):
        # Only alert for successful PutBucketLifecycle events
        if not (aws_cloudtrail_success(event) and event.get("eventName") == "PutBucketLifecycle"):
            return False
        # Exit out if the bucket doesn't have cloudtrail logs
        #   We check this be either comparing the bucket name to a list of buckets the user knows has
        #   CT logs, or by heuristically looking at the name and guessing whether it likely has CT logs
        bucket_name = event.deep_get("requestParameters", "bucketName")
        if not bucket_name or (
            not self.is_cloudtrail_bucket(bucket_name) and (not self.guess_is_cloudtrail_bucket(bucket_name))
        ):
            return False
        # Don't alert if the Rule status is disabled
        lifecycle = event.deep_get("requestParameters", "LifecycleConfiguration", "Rule")
        if lifecycle.get("Status") != "Enabled":
            return False
        # Alert if the lifecycle period is short
        duration = deep_get(lifecycle, "Expiration", "Days", default=0)
        return duration < self.CLOUDTRAIL_MINIMUM_STORAGE_PERIOD_DAYS

    def title(self, event):
        bucket_name = event.deep_get("requestParameters", "bucketName", default="<UNKNOWN S3 BUCKET>")
        lifecycle = event.deep_get("requestParameters", "LifecycleConfiguration", "Rule")
        duration = deep_get(lifecycle, "Expiration", "Days", default=0)
        rule_id = lifecycle.get("ID", "<UNKNOWN RULE ID>")
        account = event.deep_get("userIdentity", "accountId", default="<UNKNOWN_AWS_ACCOUNT>")
        return f"S3 Bucket {bucket_name} in account {lookup_aws_account_name(account)} has new rule {rule_id} set to delete CloudTrail logs after {duration} day{('s' if duration != 1 else '')}"

    def severity(self, event):
        # Return lower severity if we aren't positive this bucket has cloudtrail logs.
        bucket_name = event.deep_get("requestParameters", "bucketName")
        if not self.is_cloudtrail_bucket(bucket_name):
            return "LOW"
        return "DEFAULT"

    def alert_context(self, event):
        context = aws_rule_context(event)
        # Add name of S3 bucket, Rule ID, and expiration duration to context
        bucket_name = event.deep_get("requestParameters", "bucketName", default="<UNKNOWN S3 BUCKET>")
        lifecycle = event.deep_get("requestParameters", "LifecycleConfiguration", "Rule")
        duration = deep_get(lifecycle, "Expiration", "Days", default=0)
        rule_id = lifecycle.get("ID", "<UNKNOWN RULE ID>")
        context.update({"bucketName": bucket_name, "lifecycleRuleID": rule_id, "lifecycleRuleDurationDays": duration})
        return context

    def is_cloudtrail_bucket(self, bucket_name: str) -> bool:
        """Returns True if the bucket is known to contain CloudTrail logs."""
        return bucket_name in self.CLOUDTRAIL_BUCKETS

    def guess_is_cloudtrail_bucket(self, bucket_name: str) -> bool:
        """Takes a best guess at whether a bucket contains CloudTrail logs or not."""
        # Maybe one day, this check will get more complex
        return "trail" in bucket_name.lower()

    tests = [
        RuleTest(
            name="1-Day Lifecycle Rule on Known CT Bucket",
            expected_result=True,
            mocks=[RuleMock(object_name="is_cloudtrail_bucket", return_value="true")],
            log={
                "p_event_time": "2024-11-25 22:00:58.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2024-11-25 22:05:54.357893092",
                "additionalEventData": {
                    "AuthenticationMethod": "AuthHeader",
                    "CipherSuite": "TLS_AES_128_GCM_SHA256",
                    "SignatureVersion": "SigV4",
                    "bytesTransferredIn": 249,
                    "bytesTransferredOut": 0,
                    "x-amz-id-2": "vf6Ehji6uE8ET3EJvRpIQva7eul9KSAUWVlf87sIKBmLQ0HgdGbswZiHYlVvSr1FdP5DiZze4DRZRAFppKpD4A==",
                },
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "e1ea136d-f372-4cd5-be5f-f317fc80214a",
                "eventName": "PutBucketLifecycle",
                "eventSource": "s3.amazonaws.com",
                "eventTime": "2024-11-25 22:00:58.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.10",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "111122223333",
                "requestID": "4XRNRGRFH6RES629",
                "requestParameters": {
                    "Host": "sample-cloudtrail-bucket-name.s3.us-west-2.amazonaws.com",
                    "LifecycleConfiguration": {
                        "Rule": {
                            "Expiration": {"Days": 1},
                            "Filter": {"Prefix": "*"},
                            "ID": "nuke-cloudtrail-logs-after-1-day",
                            "Status": "Enabled",
                        },
                        "xmlns": "http://s3.amazonaws.com/doc/2006-03-01/",
                    },
                    "bucketName": "sample-cloudtrail-bucket-name",
                    "lifecycle": "",
                },
                "resources": [
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:s3:::sample-cloudtrail-bucket-name",
                        "type": "AWS::S3::Bucket",
                    },
                ],
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "sample-cloudtrail-bucket-name.s3.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "[sample-user-agent]",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/leroy.jenkins",
                    "principalId": "SAMPLE_PRINCIPAL_ID:leroy.jenkins",
                    "sessionContext": {
                        "attributes": {"creationDate": "2024-11-25T16:53:42Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
                            "principalId": "SAMPLE_PRINCIPAL_ID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="1-Day Lifecycle Rule on Assumed CT Bucket",
            expected_result=True,
            mocks=[RuleMock(object_name="is_cloudtrail_bucket", return_value="")],
            log={
                "p_event_time": "2024-11-25 22:00:58.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2024-11-25 22:05:54.357893092",
                "additionalEventData": {
                    "AuthenticationMethod": "AuthHeader",
                    "CipherSuite": "TLS_AES_128_GCM_SHA256",
                    "SignatureVersion": "SigV4",
                    "bytesTransferredIn": 249,
                    "bytesTransferredOut": 0,
                    "x-amz-id-2": "vf6Ehji6uE8ET3EJvRpIQva7eul9KSAUWVlf87sIKBmLQ0HgdGbswZiHYlVvSr1FdP5DiZze4DRZRAFppKpD4A==",
                },
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "e1ea136d-f372-4cd5-be5f-f317fc80214a",
                "eventName": "PutBucketLifecycle",
                "eventSource": "s3.amazonaws.com",
                "eventTime": "2024-11-25 22:00:58.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.10",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "111122223333",
                "requestID": "4XRNRGRFH6RES629",
                "requestParameters": {
                    "Host": "sample-cloudtrail-bucket-name.s3.us-west-2.amazonaws.com",
                    "LifecycleConfiguration": {
                        "Rule": {
                            "Expiration": {"Days": 1},
                            "Filter": {"Prefix": "*"},
                            "ID": "nuke-cloudtrail-logs-after-1-day",
                            "Status": "Enabled",
                        },
                        "xmlns": "http://s3.amazonaws.com/doc/2006-03-01/",
                    },
                    "bucketName": "sample-cloudtrail-bucket-name",
                    "lifecycle": "",
                },
                "resources": [
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:s3:::sample-cloudtrail-bucket-name",
                        "type": "AWS::S3::Bucket",
                    },
                ],
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "sample-cloudtrail-bucket-name.s3.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "[sample-user-agent]",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/leroy.jenkins",
                    "principalId": "SAMPLE_PRINCIPAL_ID:leroy.jenkins",
                    "sessionContext": {
                        "attributes": {"creationDate": "2024-11-25T16:53:42Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
                            "principalId": "SAMPLE_PRINCIPAL_ID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Disabled 1-Day Lifecycle Rule on Known CT Bucket",
            expected_result=False,
            mocks=[RuleMock(object_name="is_cloudtrail_bucket", return_value="true")],
            log={
                "p_event_time": "2024-11-25 22:00:58.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2024-11-25 22:05:54.357893092",
                "additionalEventData": {
                    "AuthenticationMethod": "AuthHeader",
                    "CipherSuite": "TLS_AES_128_GCM_SHA256",
                    "SignatureVersion": "SigV4",
                    "bytesTransferredIn": 249,
                    "bytesTransferredOut": 0,
                    "x-amz-id-2": "vf6Ehji6uE8ET3EJvRpIQva7eul9KSAUWVlf87sIKBmLQ0HgdGbswZiHYlVvSr1FdP5DiZze4DRZRAFppKpD4A==",
                },
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "e1ea136d-f372-4cd5-be5f-f317fc80214a",
                "eventName": "PutBucketLifecycle",
                "eventSource": "s3.amazonaws.com",
                "eventTime": "2024-11-25 22:00:58.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.10",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "111122223333",
                "requestID": "4XRNRGRFH6RES629",
                "requestParameters": {
                    "Host": "sample-cloudtrail-bucket-name.s3.us-west-2.amazonaws.com",
                    "LifecycleConfiguration": {
                        "Rule": {
                            "Expiration": {"Days": 1},
                            "Filter": {"Prefix": "*"},
                            "ID": "nuke-cloudtrail-logs-after-1-day",
                            "Status": "Disabled",
                        },
                        "xmlns": "http://s3.amazonaws.com/doc/2006-03-01/",
                    },
                    "bucketName": "sample-cloudtrail-bucket-name",
                    "lifecycle": "",
                },
                "resources": [
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:s3:::sample-cloudtrail-bucket-name",
                        "type": "AWS::S3::Bucket",
                    },
                ],
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "sample-cloudtrail-bucket-name.s3.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "[sample-user-agent]",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/leroy.jenkins",
                    "principalId": "SAMPLE_PRINCIPAL_ID:leroy.jenkins",
                    "sessionContext": {
                        "attributes": {"creationDate": "2024-11-25T16:53:42Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
                            "principalId": "SAMPLE_PRINCIPAL_ID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="730-Day Lifecycle Rule on Known CT Bucket",
            expected_result=False,
            mocks=[RuleMock(object_name="is_cloudtrail_bucket", return_value="true")],
            log={
                "p_event_time": "2024-11-26 17:26:06.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2024-11-26 17:30:54.113261939",
                "additionalEventData": {
                    "AuthenticationMethod": "AuthHeader",
                    "CipherSuite": "TLS_AES_128_GCM_SHA256",
                    "SignatureVersion": "SigV4",
                    "bytesTransferredIn": 309,
                    "bytesTransferredOut": 0,
                    "x-amz-id-2": "xdjFGuP5MOmtnO6PCaHFNtvmnmUjGLngYLZlKRtdDAihd76he3U1M1QVXbs0q5vZr4Pv7ipRNUU=",
                },
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "a8cfbde4-3b77-430a-b2f3-388d5bb75eb3",
                "eventName": "PutBucketLifecycle",
                "eventSource": "s3.amazonaws.com",
                "eventTime": "2024-11-26 17:26:06.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.10",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "111122223333",
                "requestID": "HAKZ6Z7PDPHET3TQ",
                "requestParameters": {
                    "Host": "s3.us-west-2.amazonaws.com",
                    "LifecycleConfiguration": {
                        "Rule": {
                            "Expiration": {"Days": 730},
                            "Filter": "",
                            "ID": "nuke-cloudtrail-logs-after-730-days",
                            "NoncurrentVersionExpiration": {"NoncurrentDays": 730},
                            "Status": "Enabled",
                        },
                        "xmlns": "http://s3.amazonaws.com/doc/2006-03-01/",
                    },
                    "bucketName": "sample-cloudtrail-bucket-name",
                    "lifecycle": "",
                },
                "resources": [
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:s3:::sample-cloudtrail-bucket-name",
                        "type": "AWS::S3::Bucket",
                    },
                ],
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "s3.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "[Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36]",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/leroy.jenkins",
                    "principalId": "SAMPLE_PRINCIPAL_ID:leroy.jenkins",
                    "sessionContext": {
                        "attributes": {"creationDate": "2024-11-26T17:23:25Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
                            "principalId": "SAMPLE_PRINCIPAL_ID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Completely Unrelated Event",
            expected_result=False,
            log={
                "p_event_time": "2024-11-26 17:23:59.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2024-11-26 17:30:54.112906272",
                "additionalEventData": {
                    "AuthenticationMethod": "AuthHeader",
                    "CipherSuite": "TLS_AES_128_GCM_SHA256",
                    "SignatureVersion": "SigV4",
                    "bytesTransferredIn": 0,
                    "bytesTransferredOut": 313,
                    "x-amz-id-2": "CaKGcLO+fHGAWCSQD7+2dEACPcs+Az44FEQT3c5iu+YlJ8sFA++rPcYTr5xGx5/iwaxNWzWWaWQ=",
                },
                "awsRegion": "us-west-2",
                "errorCode": "NoSuchLifecycleConfiguration",
                "errorMessage": "The lifecycle configuration does not exist",
                "eventCategory": "Management",
                "eventID": "41fd8553-6e3c-4942-ad03-aba324ec109e",
                "eventName": "GetBucketLifecycle",
                "eventSource": "s3.amazonaws.com",
                "eventTime": "2024-11-26 17:23:59.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.10",
                "managementEvent": True,
                "readOnly": True,
                "recipientAccountId": "111122223333",
                "requestID": "BTYKZ7VY1EKRSMZM",
                "requestParameters": {
                    "Host": "s3.us-west-2.amazonaws.com",
                    "bucketName": "sample-cloudtrail-bucket-name",
                    "lifecycle": "",
                },
                "resources": [
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:s3:::sample-cloudtrail-bucket-name",
                        "type": "AWS::S3::Bucket",
                    },
                ],
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "s3.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "[Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36]",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/leroy.jenkins",
                    "principalId": "SAMPLE_PRINCIPAL_ID:leroy.jenkins",
                    "sessionContext": {
                        "attributes": {"creationDate": "2024-11-26T17:23:25Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
                            "principalId": "SAMPLE_PRINCIPAL_ID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
    ]
