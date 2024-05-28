from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_iocs import CRYPTO_MINING_DOMAINS
from pypanther.log_types import LogType

awsdns_crypto_domain_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Non Crypto Query",
        ExpectedResult=False,
        Log={
            "account_id": "0123456789",
            "answers": [{"Class": "IN", "Rdata": "1.2.3.4", "Type": "A"}],
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
        },
    ),
    PantherRuleTest(
        Name="Non Crypto Query Trailing Period",
        ExpectedResult=False,
        Log={
            "account_id": "0123456789",
            "answers": [{"Class": "IN", "Rdata": "1.2.3.4", "Type": "A"}],
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
        },
    ),
    PantherRuleTest(
        Name="Crypto Query",
        ExpectedResult=True,
        Log={
            "account_id": "0123456789",
            "answers": [{"Class": "IN", "Rdata": "1.2.3.4", "Type": "A"}],
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
        },
    ),
    PantherRuleTest(
        Name="Crypto Query Subdomain",
        ExpectedResult=True,
        Log={
            "account_id": "0123456789",
            "answers": [{"Class": "IN", "Rdata": "1.2.3.4", "Type": "A"}],
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
        },
    ),
    PantherRuleTest(
        Name="Crypto Query Trailing Period",
        ExpectedResult=True,
        Log={
            "account_id": "0123456789",
            "answers": [{"Class": "IN", "Rdata": "1.2.3.4", "Type": "A"}],
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
        },
    ),
    PantherRuleTest(
        Name="Crypto Query Subdomain Trailing Period",
        ExpectedResult=True,
        Log={
            "account_id": "0123456789",
            "answers": [{"Class": "IN", "Rdata": "1.2.3.4", "Type": "A"}],
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
        },
    ),
    PantherRuleTest(
        Name="Checking Against Subdomain IOC",
        ExpectedResult=True,
        Log={
            "account_id": "0123456789",
            "answers": [{"Class": "IN", "Rdata": "1.2.3.4", "Type": "A"}],
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
        },
    ),
    PantherRuleTest(
        Name="Checking Against Subdomain IOC Trailing Period",
        ExpectedResult=True,
        Log={
            "account_id": "0123456789",
            "answers": [{"Class": "IN", "Rdata": "1.2.3.4", "Type": "A"}],
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
        },
    ),
]


class AWSDNSCryptoDomain(PantherRule):
    Description = "Identifies clients that may be performing DNS lookups associated with common currency mining pools."
    DisplayName = "AWS DNS Crypto Domain"
    Reports = {"MITRE ATT&CK": ["TA0040:T1496"]}
    Reference = "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"
    Severity = PantherSeverity.High
    LogTypes = [LogType.AWS_VPCDns]
    RuleID = "AWS.DNS.Crypto.Domain-prototype"
    Tests = awsdns_crypto_domain_tests

    def rule(self, event):
        query_name = event.get("query_name")
        for domain in CRYPTO_MINING_DOMAINS:
            if query_name.rstrip(".").endswith(domain):
                return True
        return False

    def title(self, event):
        return f"[{event.get('srcaddr')}:{event.get('srcport')}] made a DNS query for crypto mining domain: [{event.get('query_name')}]."

    def dedup(self, event):
        return f"{event.get('srcaddr')}"
