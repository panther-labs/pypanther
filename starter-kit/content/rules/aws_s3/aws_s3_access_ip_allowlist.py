from ipaddress import IPv4Network, IPv6Network, ip_network

from panther_aws_helpers import aws_rule_context

from pypanther import LogType, Rule, RuleTest, Severity


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
    # Example bucket names to watch go here
    BUCKETS_TO_MONITOR = {}
    # IP addresses (in CIDR notation) indicating approved IP ranges for accessing S3 buckets}
    ALLOWLIST_NETWORKS = {ip_network("10.0.0.0/8"), ip_network("172.16.0.0/12"), ip_network("192.168.0.0/16")}

    def rule(self, event):
        if self.BUCKETS_TO_MONITOR:
            if event.get("bucket") not in self.BUCKETS_TO_MONITOR:
                return False
        if "remoteip" not in event:
            return False
        cidr_ip = ip_network(event.get("remoteip"))
        return not any(self.is_subnet(approved_ip_range, cidr_ip) for approved_ip_range in self.ALLOWLIST_NETWORKS)

    def title(self, event):
        return f"Non-Approved IP access to S3 Bucket [{event.get('bucket', '<UNKNOWN_BUCKET>')}]"

    def alert_context(self, event):
        return aws_rule_context(event)

    def is_subnet(self, supernet: IPv4Network | IPv6Network, subnet: IPv4Network | IPv6Network) -> bool:
        """Return true if 'subnet' is a subnet of 'supernet'"""
        # We can't do a classic subnet comparison between v4 and v6 networks, so we have to explictly
        #   check for version mismatch first
        if supernet.network_address.version != subnet.network_address.version:
            return False
        # Else, do the subnet calculation
        return subnet.subnet_of(supernet)

    tests = [
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
        RuleTest(
            name="Access From IPv6",
            expected_result=True,
            log={"remoteip": "2600:1ffe:8140::a47:a85a", "bucket": "my-test-bucket"},
        ),
    ]
