from ipaddress import ip_network
from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context
from pypanther.log_types import LogType

awss3_server_access_ip_whitelist_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Access From Approved IP",
        ExpectedResult=False,
        Log={"remoteip": "10.0.0.1", "bucket": "my-test-bucket"},
    ),
    PantherRuleTest(
        Name="Access From Unapproved IP",
        ExpectedResult=True,
        Log={"remoteip": "11.0.0.1", "bucket": "my-test-bucket"},
    ),
]


class AWSS3ServerAccessIPWhitelist(PantherRule):
    RuleID = "AWS.S3.ServerAccess.IPWhitelist-prototype"
    DisplayName = "AWS S3 Access IP Allowlist"
    Enabled = False
    LogTypes = [LogType.AWS_S3ServerAccess]
    Tags = [
        "AWS",
        "Configuration Required",
        "Identity & Access Management",
        "Collection:Data From Cloud Storage Object",
    ]
    Reports = {"MITRE ATT&CK": ["TA0009:T1530"]}
    Severity = PantherSeverity.Medium
    Description = "Checks that the remote IP accessing the S3 bucket is in the IP allowlist.\n"
    Runbook = "Verify whether unapproved access of S3 objects occurred, and take appropriate steps to remediate damage (for example, informing related parties of unapproved access and potentially invalidating data that was accessed). Consider updating the access policies of the S3 bucket to prevent future unapproved access.\n"
    Reference = "https://aws.amazon.com/premiumsupport/knowledge-center/block-s3-traffic-vpc-ip/"
    SummaryAttributes = ["bucket", "key", "remoteip"]
    Tests = awss3_server_access_ip_whitelist_tests
    # Example bucket names to watch go here
    BUCKETS_TO_MONITOR = {}
    # IP addresses (in CIDR notation) indicating approved IP ranges for accessing S3 buckets}
    ALLOWLIST_NETWORKS = {ip_network("10.0.0.0/8")}

    def rule(self, event):
        if self.BUCKETS_TO_MONITOR:
            if event.get("bucket") not in self.BUCKETS_TO_MONITOR:
                return False
        if "remoteip" not in event:
            return False
        cidr_ip = ip_network(event.get("remoteip"))
        return not any(
            (cidr_ip.subnet_of(approved_ip_range) for approved_ip_range in self.ALLOWLIST_NETWORKS)
        )

    def title(self, event):
        return f"Non-Approved IP access to S3 Bucket [{event.get('bucket', '<UNKNOWN_BUCKET>')}]"

    def alert_context(self, event):
        return aws_rule_context(event)
