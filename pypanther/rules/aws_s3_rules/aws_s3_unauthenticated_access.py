from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context

awss3_server_access_unauthenticated_tests: list[RuleTest] = [
    RuleTest(
        name="Authenticated Access",
        expected_result=False,
        log={
            "bucket": "example-bucket",
            "requester": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be",
        },
    ),
    RuleTest(name="Unauthenticated Access", expected_result=True, log={"bucket": "example-bucket"}),
]


@panther_managed
class AWSS3ServerAccessUnauthenticated(Rule):
    id = "AWS.S3.ServerAccess.Unauthenticated-prototype"
    display_name = "AWS S3 Unauthenticated Access"
    enabled = False
    log_types = [LogType.AWS_S3_SERVER_ACCESS]
    tags = ["AWS", "Configuration Required", "Security Control", "Collection:Data From Cloud Storage Object"]
    reports = {"MITRE ATT&CK": ["TA0009:T1530"]}
    default_severity = Severity.LOW
    default_description = "Checks for S3 access attempts where the requester is not an authenticated AWS user.\n"
    default_runbook = "If unauthenticated S3 access is not expected for this bucket, update its access policies.\n"
    default_reference = (
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-auth-workflow-bucket-operation.html"
    )
    summary_attributes = ["bucket", "key", "requester"]
    tests = awss3_server_access_unauthenticated_tests
    # A list of buckets where authenticated access is expected
    AUTH_BUCKETS = {"example-bucket"}

    def rule(self, event):
        return event.get("bucket") in self.AUTH_BUCKETS and (not event.get("requester"))

    def title(self, event):
        return f"Unauthenticated access to S3 Bucket [{event.get('bucket', '<UNKNOWN_BUCKET')}]"

    def alert_context(self, event):
        return aws_rule_context(event)
