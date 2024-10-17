from fnmatch import fnmatch

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSS3ServerAccessUnknownRequester(Rule):
    id = "AWS.S3.ServerAccess.UnknownRequester-prototype"
    display_name = "AWS S3 Unknown Requester"
    enabled = False
    log_types = [LogType.AWS_S3_SERVER_ACCESS]
    tags = ["AWS", "Configuration Required", "Security Control", "Collection:Data From Cloud Storage Object"]
    reports = {"Panther": ["Data Access"], "MITRE ATT&CK": ["TA0009:T1530"]}
    default_severity = Severity.LOW
    default_description = "Validates that proper IAM entities are accessing sensitive data buckets."
    default_runbook = "If the S3 access is not expected for this bucket, investigate the requester's other traffic."
    default_reference = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/walkthrough1.html"
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
    # pylint: disable=line-too-long
    BUCKET_ROLE_MAPPING = {
        "panther-bootstrap-processeddata-*": [
            "arn:aws:sts::*:assumed-role/panther-cloud-security-EventProcessorFunctionRole-*/panther-aws-event-processor",
            "arn:aws:sts::*:assumed-role/panther-log-analysis-AthenaApiFunctionRole-*/panther-athena-api",
            "arn:aws:sts::*:assumed-role/panther-log-analysis-RulesEngineFunctionRole-*/panther-rules-engine",
            "arn:aws:sts::*:assumed-role/panther-snowflake-logprocessing-role-*/snowflake",
            "arn:aws:sts::*:assumed-role/panther-data-replication-role-*/s3-replication",
        ],
    }
    # pylint: enable=line-too-long

    def _unknown_requester_access(self, event):
        for bucket_pattern, role_patterns in self.BUCKET_ROLE_MAPPING.items():
            if not fnmatch(event.get("bucket", ""), bucket_pattern):
                continue
            if not any(fnmatch(event.get("requester", ""), role_pattern) for role_pattern in role_patterns):
                return True
        return False

    def rule(self, event):
        if event.get("errorcode"):
            return False
        return event.get("operation") == "REST.GET.OBJECT" and self._unknown_requester_access(event)

    def title(self, event):
        return f"Unknown requester accessing data from S3 Bucket [{event.get('bucket', '<UNKNOWN_BUCKET>')}]"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Expected Access",
            expected_result=False,
            log={
                "bucketowner": "f16a9e81a6589df1c902c86f7982fd14a88787db",
                "bucket": "panther-bootstrap-processeddata-AF1341JAK",
                "time": "2020-02-14 00:53:48.000000000",
                "remoteip": "127.0.0.1",
                "requester": "arn:aws:sts::123456789012:assumed-role/panther-log-analysis-AthenaApiFunctionRole-1KK31J1/panther-athena-api",
                "requestid": "101B7403B9828743",
                "operation": "REST.GET.OBJECT",
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
            },
        ),
        RuleTest(
            name="Unexpected Access",
            expected_result=True,
            log={
                "bucketowner": "f16a9e81a6589df1c902c86f7982fd14a88787db",
                "bucket": "panther-bootstrap-processeddata-AF1341JAK",
                "time": "2020-02-14 00:53:48.000000000",
                "remoteip": "127.0.0.1",
                "requester": "arn:aws:iam::123456789012:user/jim-bob",
                "requestid": "101B7403B9828743",
                "operation": "REST.GET.OBJECT",
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
            },
        ),
        RuleTest(
            name="Failed Request",
            expected_result=False,
            log={
                "bucketowner": "f16a9e81a6589df1c902c86f7982fd14a88787db",
                "bucket": "panther-bootstrap-processeddata-AF1341JAK",
                "time": "2020-02-14 00:53:48.000000000",
                "errorcode": "AuthorizationHeaderMalformed",
                "remoteip": "127.0.0.1",
                "requestid": "101B7403B9828743",
                "operation": "REST.GET.OBJECT",
                "key": "AWSLogs/o-wwwwwwgggg/234567890123/CloudTrail-Digest/ca-central-1/2020/02/14/234567890123_CloudTrail-Digest_ca-central-1_POrgTrail_us-east-1_20200214T001007Z.json.gz",
                "requesturi": "PUT /AWSLogs/o-wwwwwwgggg/234567890123/CloudTrail-Digest/ca-central-1/2020/02/14/234567890123_CloudTrail-Digest_ca-central-1_POrgTrail_us-east-1_20200214T001007Z.json.gz HTTP/1.1",
                "httpstatus": 400,
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
            },
        ),
        RuleTest(
            name="Snowflake Request",
            expected_result=False,
            log={
                "authenticationtype": "AuthHeader",
                "bucket": "panther-bootstrap-processeddata-AF1341JAK",
                "bucketowner": "f16a9e81a6589df1c902c86f7982fd14a88787db",
                "ciphersuite": "ECDHE-RSA-AES128-GCM-SHA256",
                "httpstatus": 200,
                "key": "logs/logdir/year%253D2020/month%253D09/day%253D30/hour%253D19/file.json.gz",
                "requesturi": "GET /logs/logdir/year%3D2020/month%3D09/day%3D30/hour%3D19/file.json.gz HTTP/1.1",
                "objectsize": 4063,
                "operation": "REST.GET.OBJECT",
                "remoteip": "127.0.0.1",
                "requester": "arn:aws:sts::123456789012:assumed-role/panther-snowflake-logprocessing-role-us-west-2/snowflake",
                "requestid": "101B7403B9828743",
                "signatureversion": "SigV4",
                "time": "2020-09-30 20:49:19.000000000",
                "tlsVersion": "TLSv1.2",
                "totaltime": 10,
                "turnaroundtime": 9,
                "useragent": "snowflake/1.0",
            },
        ),
    ]
