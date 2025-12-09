from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSS3DisableBucketLogging(Rule):
    id = "AWS.S3.DisableBucketLogging-prototype"
    display_name = "S3 Bucket Logging Disabled"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Defense Evasion", "Impact:Data Destruction"]
    reports = {"MITRE ATT&CK": ["TA0005:T1562", "TA0040:T1485"]}
    default_severity = Severity.LOW
    status = "Experimental"
    default_description = "Detects when server access logging is disabled on an S3 bucket, removing audit trail capabilities that could indicate ransomware preparation activity or an attempt to evade detection."
    default_runbook = "1. Query CloudTrail for all S3 API calls by the userIdentity:arn on the requestParameters:bucketName in the 24 hours before and after the bucket logging was disabled to identify if this is part of a larger attack pattern\n2. Check if this user has modified bucket logging configurations in the past 90 days to determine if this is normal administrative activity\n3. Find other alerts with rule IDs AWS.S3.SuspendVersioning, AWS.S3.DisableMfaDelete, or AWS.S3.DeleteBucketEncryption for the same bucket in the past 7 days to detect coordinated security control disabling\n"
    default_reference = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html"
    summary_attributes = ["sourceIpAddress", "userAgent", "recipientAccountId", "p_any_aws_arns"]

    def rule(self, event):
        return (
            aws_cloudtrail_success(event)
            and event.get("eventSource") == "s3.amazonaws.com"
            and (event.get("eventName") == "PutBucketLogging")
            and (event.deep_get("requestParameters", "logging") == "")
        )

    def title(self, event):
        return f"[AWS.CloudTrail] User [{event.udm('actor_user')}] disabled bucket logging for bucket [{event.deep_get('requestParameters', 'bucketName')}]"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Bucket Logging Disabled Successfully",
            expected_result=True,
            log={
                "eventVersion": "1.11",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "AAAAAAAAAAAAAAAAAAAAA:user_name",
                    "arn": "arn:aws:sts::111111111111:assumed-role/sample-role-dreamy-yonath/sample-role-brave-yalow-role-intelligent-brahmagupta-role-beautiful-keldysh-role-happy-easley-role-bold-buck",
                    "accountId": "111111111111",
                    "accessKeyId": "ASIA-MOCKACCESSKEYID-1",
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "AAAAAAAAAAAAAAAAAAAAA",
                            "arn": "arn:aws:iam::111111111111:role/sample-role-quirky-greider/sso.amazonaws.com/us-west-2/sample-role-dreamy-yonath",
                            "accountId": "111111111111",
                            "userName": "AdminRole",
                        },
                        "attributes": {"creationDate": "2024-01-15T10:30:00Z", "mfaAuthenticated": "false"},
                    },
                },
                "eventTime": "2024-01-15T10:45:23Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutBucketLogging",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "[Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36]",
                "requestParameters": {
                    "logging": "",
                    "bucketName": "critical-data-bucket",
                    "BucketLoggingStatus": {"xmlns": "http://s3.amazonaws.com/doc/2006-03-01/"},
                    "Host": "sample-bucket-great-proskuriakova.s3.us-west-2.amazonaws.com",
                },
                "responseElements": None,
                "additionalEventData": {
                    "SignatureVersion": "SigV4",
                    "CipherSuite": "TLS_AES_128_GCM_SHA256",
                    "bytesTransferredIn": 108,
                    "AuthenticationMethod": "AuthHeader",
                    "x-amz-id-2": "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ12345678901234567890==",
                    "bytesTransferredOut": 0,
                },
                "requestID": "ABC123DEF456",
                "eventID": "12345678-1234-1234-1234-111111111111",
                "readOnly": False,
                "resources": [
                    {
                        "accountId": "111111111111",
                        "type": "AWS::S3::Bucket",
                        "ARN": "arn:aws:s3:::sample-bucket-great-proskuriakova",
                    },
                ],
                "eventType": "AwsApiCall",
                "managementEvent": True,
                "recipientAccountId": "111111111111",
                "eventCategory": "Management",
                "tlsDetails": {
                    "tlsVersion": "TLSv1.3",
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "sample-bucket-great-proskuriakova.s3.us-west-2.amazonaws.com",
                },
            },
        ),
        RuleTest(
            name="Bucket Logging Disabled - Failed",
            expected_result=False,
            log={
                "eventVersion": "1.11",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AIDAI23HXS4EXAMPLE",
                    "arn": "arn:aws:iam::111111111111:user/testuser",
                    "accountId": "111111111111",
                    "accessKeyId": "AKIA-MOCKACCESSKEYID-1",
                },
                "eventTime": "2024-01-15T10:45:23Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutBucketLogging",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "[Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36]",
                "errorCode": "AccessDenied",
                "errorMessage": "Access Denied",
                "requestParameters": {
                    "logging": "",
                    "bucketName": "critical-data-bucket",
                    "BucketLoggingStatus": {"xmlns": "http://s3.amazonaws.com/doc/2006-03-01/"},
                    "Host": "sample-bucket-great-proskuriakova.s3.us-west-2.amazonaws.com",
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
            name="Bucket Logging Enabled",
            expected_result=False,
            log={
                "eventVersion": "1.11",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "AAAAAAAAAAAAAAAAAAAAA:user_name",
                    "arn": "arn:aws:sts::111111111111:assumed-role/sample-role-dreamy-yonath/sample-role-brave-yalow-role-intelligent-brahmagupta-role-beautiful-keldysh-role-happy-easley-role-bold-buck",
                    "accountId": "111111111111",
                    "accessKeyId": "ASIA-MOCKACCESSKEYID-1",
                },
                "eventTime": "2024-01-15T10:45:23Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutBucketLogging",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "[Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36]",
                "requestParameters": {
                    "logging": [{"targetBucket": "logging-bucket", "targetPrefix": "logs/"}],
                    "bucketName": "critical-data-bucket",
                    "BucketLoggingStatus": {
                        "xmlns": "http://s3.amazonaws.com/doc/2006-03-01/",
                        "LoggingEnabled": {"TargetBucket": "logging-bucket", "TargetPrefix": "logs/"},
                    },
                    "Host": "sample-bucket-great-proskuriakova.s3.us-west-2.amazonaws.com",
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
            name="Logging Field Missing",
            expected_result=False,
            log={
                "eventVersion": "1.11",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "AAAAAAAAAAAAAAAAAAAAA:user_name",
                    "arn": "arn:aws:sts::111111111111:assumed-role/AdminRole/user_name",
                    "accountId": "111111111111",
                    "accessKeyId": "ASIA-MOCKACCESSKEYID-1",
                },
                "eventTime": "2024-01-15T10:45:23Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutBucketLogging",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.10.0-1234-aws exe/x86_64.ubuntu.22",
                "requestParameters": {
                    "bucketName": "critical-data-bucket",
                    "Host": "critical-data-bucket.s3.us-west-2.amazonaws.com",
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
    ]
