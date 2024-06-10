from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_iocs import CRYPTO_MINING_DOMAINS
from pypanther.log_types import PantherLogType

awsdns_crypto_domain_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Non Crypto Query",
        ExpectedResult=False,
        Log={
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
    PantherRuleTest(
        Name="Non Crypto Query Trailing Period",
        ExpectedResult=False,
        Log={
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
    PantherRuleTest(
        Name="Crypto Query",
        ExpectedResult=True,
        Log={
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
    PantherRuleTest(
        Name="Crypto Query Subdomain",
        ExpectedResult=True,
        Log={
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
    PantherRuleTest(
        Name="Crypto Query Trailing Period",
        ExpectedResult=True,
        Log={
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
    PantherRuleTest(
        Name="Crypto Query Subdomain Trailing Period",
        ExpectedResult=True,
        Log={
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
    PantherRuleTest(
        Name="Checking Against Subdomain IOC",
        ExpectedResult=True,
        Log={
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
    PantherRuleTest(
        Name="Checking Against Subdomain IOC Trailing Period",
        ExpectedResult=True,
        Log={
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
    PantherRuleTest(
        Name="Non Crypto Query Trailing Period - OCSF",
        ExpectedResult=False,
        Log={
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
            "query": {
                "class": "IN",
                "hostname": "dynamodb.us-west-2.amazonaws.com.",
                "type": "AAAA",
            },
            "rcode": "NoError",
            "rcode_id": 0,
            "severity": "Informational",
            "severity_id": 1,
            "src_endpoint": {
                "instance_uid": "i-0abc234",
                "ip": "5.6.7.8",
                "port": "8888",
                "vpc_uid": "vpc-abc123",
            },
            "time": "2022-06-25 00:27:53",
            "type_name": "DNS Activity: Response",
            "type_uid": 400302,
            "p_log_type": "OCSF.DnsActivity",
        },
    ),
    PantherRuleTest(
        Name="Crypto Query - OCSF",
        ExpectedResult=True,
        Log={
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
            "src_endpoint": {
                "instance_uid": "i-0abc234",
                "ip": "5.6.7.8",
                "port": "8888",
                "vpc_uid": "vpc-abc123",
            },
            "time": "2022-06-25 00:27:53",
            "type_name": "DNS Activity: Response",
            "type_uid": 400302,
            "p_log_type": "OCSF.DnsActivity",
        },
    ),
]


class AWSDNSCryptoDomain(PantherRule):
    Description = "Identifies clients that may be performing DNS lookups associated with common currency mining pools."
    DisplayName = "AWS DNS Crypto Domain"
    Reports = {"MITRE ATT&CK": ["TA0040:T1496"]}
    Reference = "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"
    Severity = PantherSeverity.High
    LogTypes = [PantherLogType.AWS_VPCDns, PantherLogType.OCSF_DnsActivity]
    RuleID = "AWS.DNS.Crypto.Domain-prototype"
    Tests = awsdns_crypto_domain_tests

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
