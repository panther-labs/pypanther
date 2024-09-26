from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.iocs import CRYPTO_MINING_DOMAINS


@panther_managed
class AWSDNSCryptoDomain(Rule):
    default_description = (
        "Identifies clients that may be performing DNS lookups associated with common currency mining pools."
    )
    display_name = "AWS DNS Crypto Domain"
    reports = {"MITRE ATT&CK": ["TA0040:T1496"]}
    default_reference = "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"
    default_severity = Severity.HIGH
    log_types = [LogType.AWS_VPC_DNS, LogType.OCSF_DNS_ACTIVITY]
    id = "AWS.DNS.Crypto.Domain-prototype"

    def rule(self, event):
        query_name = event.udm("dns_query")
        if not query_name:
            return False
        for domain in CRYPTO_MINING_DOMAINS:
            if query_name.rstrip(".").endswith(domain):
                return True
        return False

    def title(self, event):
        return f"[{event.udm('source_ip')}:{event.udm('source_port')}] made a DNS query for crypto mining domain: [{event.udm('dns_query')}]."

    def dedup(self, event):
        return f"{event.udm('source_ip')}"

    tests = [
        RuleTest(
            name="Non Crypto Query",
            expected_result=False,
            log={
                "account_id": "0123456789",
                "answers": {"Class": "IN", "Rdata": "1.2.3.4", "Type": "A"},
                "query_class": "IN",
                "query_name": "dynamodb.us-west-2.amazonaws.com",
                "query_timestamp": "2022-06-25 00:27:53",
                "query_type": "A",
                "rcode": "NOERROR",
                "region": "us-west-2",
                "srcaddr": "5.6.7.8",
                "srcids": {"instance": "i-0abc234"},
                "srcport": "8888",
                "transport": "UDP",
                "version": "1.100000",
                "vpc_id": "vpc-abc123",
                "p_log_type": "AWS.VPCDns",
            },
        ),
        RuleTest(
            name="Non Crypto Query Trailing Period",
            expected_result=False,
            log={
                "account_id": "0123456789",
                "answers": {"Class": "IN", "Rdata": "1.2.3.4", "Type": "A"},
                "query_class": "IN",
                "query_name": "dynamodb.us-west-2.amazonaws.com.",
                "query_timestamp": "2022-06-25 00:27:53",
                "query_type": "A",
                "rcode": "NOERROR",
                "region": "us-west-2",
                "srcaddr": "5.6.7.8",
                "srcids": {"instance": "i-0abc234"},
                "srcport": "8888",
                "transport": "UDP",
                "version": "1.100000",
                "vpc_id": "vpc-abc123",
                "p_log_type": "AWS.VPCDns",
            },
        ),
        RuleTest(
            name="Crypto Query",
            expected_result=True,
            log={
                "account_id": "0123456789",
                "answers": {"Class": "IN", "Rdata": "1.2.3.4", "Type": "A"},
                "query_class": "IN",
                "query_name": "moneropool.ru",
                "query_timestamp": "2022-06-25 00:27:53",
                "query_type": "A",
                "rcode": "NOERROR",
                "region": "us-west-2",
                "srcaddr": "5.6.7.8",
                "srcids": {"instance": "i-0abc234"},
                "srcport": "8888",
                "transport": "UDP",
                "version": "1.100000",
                "vpc_id": "vpc-abc123",
                "p_log_type": "AWS.VPCDns",
            },
        ),
        RuleTest(
            name="Crypto Query Subdomain",
            expected_result=True,
            log={
                "account_id": "0123456789",
                "answers": {"Class": "IN", "Rdata": "1.2.3.4", "Type": "A"},
                "query_class": "IN",
                "query_name": "abc.abc.moneropool.ru",
                "query_timestamp": "2022-06-25 00:27:53",
                "query_type": "A",
                "rcode": "NOERROR",
                "region": "us-west-2",
                "srcaddr": "5.6.7.8",
                "srcids": {"instance": "i-0abc234"},
                "srcport": "8888",
                "transport": "UDP",
                "version": "1.100000",
                "vpc_id": "vpc-abc123",
                "p_log_type": "AWS.VPCDns",
            },
        ),
        RuleTest(
            name="Crypto Query Trailing Period",
            expected_result=True,
            log={
                "account_id": "0123456789",
                "answers": {"Class": "IN", "Rdata": "1.2.3.4", "Type": "A"},
                "query_class": "IN",
                "query_name": "moneropool.ru.",
                "query_timestamp": "2022-06-25 00:27:53",
                "query_type": "A",
                "rcode": "NOERROR",
                "region": "us-west-2",
                "srcaddr": "5.6.7.8",
                "srcids": {"instance": "i-0abc234"},
                "srcport": "8888",
                "transport": "UDP",
                "version": "1.100000",
                "vpc_id": "vpc-abc123",
                "p_log_type": "AWS.VPCDns",
            },
        ),
        RuleTest(
            name="Crypto Query Subdomain Trailing Period",
            expected_result=True,
            log={
                "account_id": "0123456789",
                "answers": {"Class": "IN", "Rdata": "1.2.3.4", "Type": "A"},
                "query_class": "IN",
                "query_name": "abc.abc.moneropool.ru.",
                "query_timestamp": "2022-06-25 00:27:53",
                "query_type": "A",
                "rcode": "NOERROR",
                "region": "us-west-2",
                "srcaddr": "5.6.7.8",
                "srcids": {"instance": "i-0abc234"},
                "srcport": "8888",
                "transport": "UDP",
                "version": "1.100000",
                "vpc_id": "vpc-abc123",
                "p_log_type": "AWS.VPCDns",
            },
        ),
        RuleTest(
            name="Checking Against Subdomain IOC",
            expected_result=True,
            log={
                "account_id": "0123456789",
                "answers": {"Class": "IN", "Rdata": "1.2.3.4", "Type": "A"},
                "query_class": "IN",
                "query_name": "webservicepag.webhop.net",
                "query_timestamp": "2022-06-25 00:27:53",
                "query_type": "A",
                "rcode": "NOERROR",
                "region": "us-west-2",
                "srcaddr": "5.6.7.8",
                "srcids": {"instance": "i-0abc234"},
                "srcport": "8888",
                "transport": "UDP",
                "version": "1.100000",
                "vpc_id": "vpc-abc123",
                "p_log_type": "AWS.VPCDns",
            },
        ),
        RuleTest(
            name="Checking Against Subdomain IOC Trailing Period",
            expected_result=True,
            log={
                "account_id": "0123456789",
                "answers": {"Class": "IN", "Rdata": "1.2.3.4", "Type": "A"},
                "query_class": "IN",
                "query_name": "webservicepag.webhop.net.",
                "query_timestamp": "2022-06-25 00:27:53",
                "query_type": "A",
                "rcode": "NOERROR",
                "region": "us-west-2",
                "srcaddr": "5.6.7.8",
                "srcids": {"instance": "i-0abc234"},
                "srcport": "8888",
                "transport": "UDP",
                "version": "1.100000",
                "vpc_id": "vpc-abc123",
                "p_log_type": "AWS.VPCDns",
            },
        ),
        RuleTest(
            name="Non Crypto Query Trailing Period - OCSF",
            expected_result=False,
            log={
                "activity_id": 2,
                "activity_name": "Response",
                "answers": [{"class": "IN", "rdata": "1.2.3.4", "type": "AAAA"}],
                "category_name": "Network Activity",
                "category_uid": 4,
                "class_name": "DNS Activity",
                "class_uid": 4003,
                "cloud": {"provider": "AWS", "region": "us-west-2"},
                "connection_info": {"direction": "Unknown", "direction_id": 0, "protocol_name": "UDP"},
                "disposition": "Unknown",
                "disposition_id": 0,
                "metadata": {
                    "product": {
                        "feature": {"name": "Resolver Query Logs"},
                        "name": "Route 53",
                        "vendor_name": "AWS",
                        "version": "1.100000",
                    },
                    "profiles": ["cloud", "security_control"],
                    "version": "1.100000",
                },
                "query": {"class": "IN", "hostname": "dynamodb.us-west-2.amazonaws.com.", "type": "AAAA"},
                "rcode": "NoError",
                "rcode_id": 0,
                "severity": "Informational",
                "severity_id": 1,
                "src_endpoint": {"instance_uid": "i-0abc234", "ip": "5.6.7.8", "port": "8888", "vpc_uid": "vpc-abc123"},
                "time": "2022-06-25 00:27:53",
                "type_name": "DNS Activity: Response",
                "type_uid": 400302,
                "p_log_type": "OCSF.DnsActivity",
            },
        ),
        RuleTest(
            name="Crypto Query - OCSF",
            expected_result=True,
            log={
                "activity_id": 2,
                "activity_name": "Response",
                "answers": [{"class": "IN", "rdata": "1.2.3.4", "type": "AAAA"}],
                "category_name": "Network Activity",
                "category_uid": 4,
                "class_name": "DNS Activity",
                "class_uid": 4003,
                "cloud": {"provider": "AWS", "region": "us-west-2"},
                "connection_info": {"direction": "Unknown", "direction_id": 0, "protocol_name": "UDP"},
                "disposition": "Unknown",
                "disposition_id": 0,
                "metadata": {
                    "product": {
                        "feature": {"name": "Resolver Query Logs"},
                        "name": "Route 53",
                        "vendor_name": "AWS",
                        "version": "1.100000",
                    },
                    "profiles": ["cloud", "security_control"],
                    "version": "1.100000",
                },
                "query": {"class": "IN", "hostname": "moneropool.ru", "type": "AAAA"},
                "rcode": "NoError",
                "rcode_id": 0,
                "severity": "Informational",
                "severity_id": 1,
                "src_endpoint": {"instance_uid": "i-0abc234", "ip": "5.6.7.8", "port": "8888", "vpc_uid": "vpc-abc123"},
                "time": "2022-06-25 00:27:53",
                "type_name": "DNS Activity: Response",
                "type_uid": 400302,
                "p_log_type": "OCSF.DnsActivity",
            },
        ),
    ]
