from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context
from pypanther.log_types import LogType

awss3_server_access_unauthenticated_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Authenticated Access",
        ExpectedResult=False,
        Log={
            "bucket": "example-bucket",
            "requester": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be",
        },
    ),
    PantherRuleTest(
        Name="Unauthenticated Access", ExpectedResult=True, Log={"bucket": "example-bucket"}
    ),
]


class AWSS3ServerAccessUnauthenticated(PantherRule):
    RuleID = "AWS.S3.ServerAccess.Unauthenticated-prototype"
    DisplayName = "AWS S3 Unauthenticated Access"
    Enabled = False
    LogTypes = [LogType.AWS_S3ServerAccess]
    Tags = [
        "AWS",
        "Configuration Required",
        "Security Control",
        "Collection:Data From Cloud Storage Object",
    ]
    Reports = {"MITRE ATT&CK": ["TA0009:T1530"]}
    Severity = PantherSeverity.Low
    Description = (
        "Checks for S3 access attempts where the requester is not an authenticated AWS user.\n"
    )
    Runbook = "If unauthenticated S3 access is not expected for this bucket, update its access policies.\n"
    Reference = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-auth-workflow-bucket-operation.html"
    SummaryAttributes = ["bucket", "key", "requester"]
    Tests = awss3_server_access_unauthenticated_tests
    # A list of buckets where authenticated access is expected
    AUTH_BUCKETS = {"example-bucket"}

    def rule(self, event):
        return event.get("bucket") in self.AUTH_BUCKETS and (not event.get("requester"))

    def title(self, event):
        return f"Unauthenticated access to S3 Bucket [{event.get('bucket', '<UNKNOWN_BUCKET')}]"

    def alert_context(self, event):
        return aws_rule_context(event)
