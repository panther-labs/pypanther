from ipaddress import ip_network

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context

awss3_server_access_ip_whitelist_tests: list[RuleTest] = [
    RuleTest(
        name="Access From Approved IP",
        expected_result=False,
        log={"remoteip": "10.0.0.1", "bucket": "my-test-bucket"},
    ),
    RuleTest(
        name="Access From Unapproved IP",
        expected_result=True,
        log={"remoteip": "11.0.0.1", "bucket": "my-test-bucket"},
    ),
]


@panther_managed
class AWSS3ServerAccessIPWhitelist(Rule):
    id = "AWS.S3.ServerAccess.IPWhitelist-prototype"
    display_name = "AWS S3 Access IP Allowlist"
    enabled = False
    log_types = [LogType.AWS_S3_SERVER_ACCESS]
    tags = [
        "AWS",
        "Configuration Required",
        "Identity & Access Management",
        "Collection:Data From Cloud Storage Object",
    ]
    reports = {"MITRE ATT&CK": ["TA0009:T1530"]}
    default_severity = Severity.MEDIUM
    default_description = "Checks that the remote IP accessing the S3 bucket is in the IP allowlist.\n"
    default_runbook = "Verify whether unapproved access of S3 objects occurred, and take appropriate steps to remediate damage (for example, informing related parties of unapproved access and potentially invalidating data that was accessed). Consider updating the access policies of the S3 bucket to prevent future unapproved access.\n"
    default_reference = "https://aws.amazon.com/premiumsupport/knowledge-center/block-s3-traffic-vpc-ip/"
    summary_attributes = ["bucket", "key", "remoteip"]
    tests = awss3_server_access_ip_whitelist_tests
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
        return not any(cidr_ip.subnet_of(approved_ip_range) for approved_ip_range in self.ALLOWLIST_NETWORKS)

    def title(self, event):
        return f"Non-Approved IP access to S3 Bucket [{event.get('bucket', '<UNKNOWN_BUCKET>')}]"

    def alert_context(self, event):
        return aws_rule_context(event)
