from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context, pattern_match

awss3_server_access_insecure_tests: list[RuleTest] = [
    RuleTest(
        name="Secure Access to S3 Bucket",
        expected_result=False,
        log={
            "bucketowner": "f16a9e81a6589df1c902c86f7982fd14a88787db",
            "bucket": "cloudtrail",
            "time": "2020-02-14 00:53:48.000000000",
            "remoteip": "127.0.0.1",
            "requester": "arn:aws:sts::123456789012:assumed-role/eagle/regionalDeliverySession",
            "requestid": "101B7403B9828743",
            "operation": "REST.PUT.OBJECT",
            "key": "AWSLogs/o-wwwwwwgggg/234567890123/CloudTrail-Digest/ca-central-1/2020/02/14/234567890123_CloudTrail-Digest_ca-central-1_POrgTrail_us-east-1_20200214T001007Z.json.gz",
            "requesturi": "PUT /AWSLogs/o-wwwwwwgggg/234567890123/CloudTrail-Digest/ca-central-1/2020/02/14/234567890123_CloudTrail-Digest_ca-central-1_POrgTrail_us-east-1_20200214T001007Z.json.gz HTTP/1.1",
            "httpstatus": 200,
            "objectsize": 747,
            "totaltime": 110,
            "turnaroundtime": 20,
            "useragent": "aws-internal/3 aws-sdk-java/1.11.714 Linux/4.9.184-0.1.ac.235.83.329.metal1.x86_64 OpenJDK_64-Bit_Server_VM/25.242-b08 java/1.8.0_242 vendor/Oracle_Corporation",
            "hostid": "neRpT/AXRsS3LMBqq/wND59opwPRWWKn7F6evEhdbS99me5fyIXpVI/MMIn6ECgU1YZAqwuF8Bw=",
            "signatureversion": "SigV4",
            "ciphersuite": "ECDHE-RSA-AES128-SHA",
            "authenticationtype": "AuthHeader",
            "hostheader": "cloudtrail.s3.us-east-1.amazonaws.com",
            "tlsVersion": "TLSv1.2",
            "p_log_type": "AWS.S3ServerAccess",
            "p_row_id": "8855aa99ff77abc8dcb0e36e0a",
            "p_event_time": "2020-02-14 00:53:48.000000000",
            "p_any_ip_addresses": ["55.99.86.234"],
            "p_any_aws_arns": ["arn:aws:sts::123456789012:assumed-role/eagle/regionalDeliverySession"],
        },
    ),
    RuleTest(
        name="Delete Marker Call",
        expected_result=False,
        log={
            "bucketowner": "06c722119dedc1896ef",
            "bucket": "panther-yyykkj4jj66e",
            "time": "2020-05-21 07:05:13.000000000",
            "requester": "AmazonS3",
            "requestid": "1366A0B06E7A7728",
            "operation": "S3.CREATE.DELETEMARKER",
            "key": "test/083ec760-bbbb-4444-8888-185614f4b0fc.csv.metadata",
            "versionid": "mNwtwD6vrqwx11g9kSpb2MDY",
            "hostid": "KxrLgSKGXXiKBBhTYbks6XeL1juvDqx+OBHflvk",
            "p_log_type": "AWS.S3ServerAccess",
            "p_row_id": "4ec7d72e6f5392c2c7c1b6e302ee01",
            "p_event_time": "2020-05-21 07:05:13.000000000",
            "p_parse_time": "2020-05-21 08:19:50.085391216",
        },
    ),
    RuleTest(
        name="Insecure Access to S3 Bucket",
        expected_result=True,
        log={
            "authenticationtype": "AuthHeader",
            "bucket": "cloudtrail",
            "bucketowner": "f16a9e81a6589df1c902c86f7982fd14a88787db",
            "hostheader": "cloudtrail.s3.us-east-1.amazonaws.com",
            "hostid": "neRpT/AXRsS3LMBqq/wND59opwPRWWKn7F6evEhdbS99me5fyIXpVI/MMIn6ECgU1YZAqwuF8Bw=",
            "httpstatus": 200,
            "key": "AWSLogs/o-wwwwwwgggg/234567890123/CloudTrail-Digest/ca-central-1/2020/02/14/234567890123_CloudTrail-Digest_ca-central-1_POrgTrail_us-east-1_20200214T001007Z.json.gz",
            "objectsize": 747,
            "operation": "REST.PUT.OBJECT",
            "p_any_aws_arns": ["arn:aws:sts::123456789012:assumed-role/eagle/regionalDeliverySession"],
            "p_any_ip_addresses": ["55.99.86.234"],
            "p_event_time": "2020-02-14 00:53:48.000000000",
            "p_log_type": "AWS.S3ServerAccess",
            "p_row_id": "8855aa99ff77abc8dcb0e36e0a",
            "remoteip": "127.0.0.1",
            "requester": "arn:aws:sts::123456789012:assumed-role/eagle/regionalDeliverySession",
            "requestid": "101B7403B9828743",
            "requesturi": "PUT /AWSLogs/o-wwwwwwgggg/234567890123/CloudTrail-Digest/ca-central-1/2020/02/14/234567890123_CloudTrail-Digest_ca-central-1_POrgTrail_us-east-1_20200214T001007Z.json.gz HTTP/1.1",
            "signatureversion": "SigV4",
            "time": "2020-02-14 00:53:48.000000000",
            "totaltime": 110,
            "turnaroundtime": 20,
            "useragent": "aws-internal/3 aws-sdk-java/1.11.714 Linux/4.9.184-0.1.ac.235.83.329.metal1.x86_64 OpenJDK_64-Bit_Server_VM/25.242-b08 java/1.8.0_242 vendor/Oracle_Corporation",
        },
    ),
]


@panther_managed
class AWSS3ServerAccessInsecure(Rule):
    id = "AWS.S3.ServerAccess.Insecure-prototype"
    display_name = "AWS S3 Insecure Access"
    dedup_period_minutes = 720
    log_types = [LogType.AWS_S3_SERVER_ACCESS]
    tags = ["AWS", "Configuration Required", "Security Control", "Collection:Data From Cloud Storage Object"]
    reports = {"MITRE ATT&CK": ["TA0009:T1530"]}
    default_severity = Severity.LOW
    default_description = (
        "Checks if HTTP (unencrypted) was used to access objects in an S3 bucket, as opposed to HTTPS (encrypted).\n"
    )
    default_runbook = "Add a condition on the S3 bucket policy that denies access via http.\n"
    default_reference = "https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule/"
    summary_attributes = [
        "bucket",
        "key",
        "operation",
        "userAgent",
        "remoteip",
        "requester",
        "p_any_aws_arns",
        "p_any_aws_account_ids",
    ]
    tests = awss3_server_access_insecure_tests

    def rule(self, event):
        return pattern_match(event.get("operation", ""), "REST.*.OBJECT") and (
            not event.get("ciphersuite") or not event.get("tlsVersion")
        )

    def title(self, event):
        return f"Insecure access to S3 Bucket [{event.get('bucket', '<UNKNOWN_BUCKET>')}]"

    def alert_context(self, event):
        return aws_rule_context(event)
