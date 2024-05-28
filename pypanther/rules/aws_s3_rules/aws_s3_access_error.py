from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, pattern_match
from pypanther.log_types import LogType

awss3_server_access_error_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Amazon Access Error",
        ExpectedResult=False,
        Log={
            "authenticationtype": "AuthHeader",
            "bucket": "cloudtrail",
            "bucketowner": "2c8e3610de4102c8e3610de4102c8e3610de410",
            "bytessent": 9438,
            "ciphersuite": "ECDHE-RSA-AES128-SHA",
            "errorcode": "SignatureDoesNotMatch",
            "hostheader": "cloudtrail.s3.us-west-2.amazonaws.com",
            "hostid": "2c8e3610de4102c8e3610de4102c8e3610de410",
            "httpstatus": 403,
            "key": "AWSLogs/o-3h3h3h3h3h/123456789012/CloudTrail/us-east-1/2020/06/21/123456789012_CloudTrail_us-east-1_20200621T2035Z_ZqQWc4WNXOQUiIic.json.gz",
            "operation": "REST.PUT.OBJECT",
            "remoteip": "54.159.198.108",
            "requestid": "8EFD962F22F2A510",
            "requesturi": "PUT /AWSLogs/o-wyibehgf3h/123456789012/CloudTrail/us-east-1/2020/06/21/123456789012_CloudTrail_us-east-1_20200621T2035Z_ZqQWc4WNXOQUiIic.json.gz HTTP/1.1",
            "signatureversion": "SigV4",
            "time": "2020-06-21 20:41:25.000000000",
            "tlsVersion": "TLSv1.2",
            "totaltime": 9,
            "useragent": "aws-internal/3",
        },
    ),
    PantherRuleTest(
        Name="Access Error",
        ExpectedResult=True,
        Log={
            "bucket": "panther-auditlogs",
            "time": "2020-04-22 07:48:45.000",
            "remoteip": "10.106.38.245",
            "requester": "arn:aws:iam::162777425019:user/awslogsdelivery",
            "requestid": "5CDAB4038253B0E4",
            "operation": "REST.GET.OBJECT",
            "httpstatus": 403,
            "errorcode": "AccessDenied",
            "tlsversion": "TLSv1.2",
        },
    ),
    PantherRuleTest(
        Name="403 on HEAD.BUCKET",
        ExpectedResult=False,
        Log={
            "bucket": "panther-auditlogs",
            "time": "2020-04-22 07:48:45.000",
            "remoteip": "10.106.38.245",
            "requester": "arn:aws:iam::162777425019:user/awslogsdelivery",
            "requestid": "5CDAB4038253B0E4",
            "operation": "REST.HEAD.BUCKET",
            "httpstatus": 403,
            "errorcode": "InternalServerError",
            "tlsversion": "TLSv1.2",
        },
    ),
    PantherRuleTest(
        Name="Internal Server Error",
        ExpectedResult=False,
        Log={
            "bucket": "panther-auditlogs",
            "time": "2020-04-22 07:48:45.000",
            "remoteip": "10.106.38.245",
            "requester": "arn:aws:iam::162777425019:user/awslogsdelivery",
            "requestid": "5CDAB4038253B0E4",
            "operation": "REST.HEAD.BUCKET",
            "httpstatus": 500,
            "errorcode": "InternalServerError",
            "tlsversion": "TLSv1.2",
        },
    ),
]


class AWSS3ServerAccessError(PantherRule):
    RuleID = "AWS.S3.ServerAccess.Error-prototype"
    DisplayName = "AWS S3 Access Error"
    DedupPeriodMinutes = 180
    Threshold = 5
    LogTypes = [LogType.AWS_S3ServerAccess]
    Tags = ["AWS", "Security Control", "Discovery:Cloud Storage Object Discovery"]
    Reports = {"MITRE ATT&CK": ["TA0007:T1619"]}
    Severity = PantherSeverity.Info
    Description = "Checks for errors during S3 Object access. This could be due to insufficient access permissions, non-existent buckets, or other reasons.\n"
    Runbook = "Investigate the specific error and determine if it is an ongoing issue that needs to be addressed or a one off or transient error that can be ignored.\n"
    Reference = "https://docs.aws.amazon.com/AmazonS3/latest/dev/ErrorCode.html"
    SummaryAttributes = ["bucket", "key", "requester", "remoteip", "operation", "errorCode"]
    Tests = awss3_server_access_error_tests
    # https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
    # Forbidden
    # Method Not Allowed
    HTTP_STATUS_CODES_TO_MONITOR = {403, 405}

    def rule(self, event):
        if event.get("useragent", "").startswith("aws-internal"):
            return False
        return (
            pattern_match(event.get("operation", ""), "REST.*.OBJECT")
            and event.get("httpstatus") in self.HTTP_STATUS_CODES_TO_MONITOR
        )

    def title(self, event):
        return f"{event.get('httpstatus')} errors found to S3 Bucket [{event.get('bucket')}]"

    def alert_context(self, event):
        return aws_rule_context(event)
