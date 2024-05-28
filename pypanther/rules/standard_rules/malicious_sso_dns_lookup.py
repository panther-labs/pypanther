from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import filter_crowdstrike_fdr_event_type
from pypanther.log_types import LogType

standard_malicious_ssodns_lookup_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Known Good SSO Domain",
        ExpectedResult=False,
        Log={
            "ContextProcessId": "440890253753908704",
            "ContextThreadId": "0",
            "ContextTimeStamp": "2022-08-31 07:03:48.879",
            "DomainName": "company_name_here.okta.com",
            "EffectiveTransmissionClass": 2,
            "Entitlements": "15",
            "RequestType": "1",
            "event_platform": "Mac",
            "event_simpleName": "DnsRequest",
            "name": "DnsRequestMacV2",
            "p_any_domain_names": ["company_name_here.okta.com"],
            "timestamp": "2022-08-31 07:03:49.195",
        },
    ),
    PantherRuleTest(
        Name="Potentially Malicious SSO Domain",
        ExpectedResult=True,
        Log={
            "ContextProcessId": "440890253753908704",
            "ContextThreadId": "0",
            "ContextTimeStamp": "2022-08-31 07:03:48.879",
            "DomainName": "company_name_here-okta.com",
            "EffectiveTransmissionClass": 2,
            "Entitlements": "15",
            "RequestType": "1",
            "event_platform": "Mac",
            "event_simpleName": "DnsRequest",
            "name": "DnsRequestMacV2",
            "p_any_domain_names": ["company_name_here-okta.com"],
            "timestamp": "2022-08-31 07:03:49.195",
        },
    ),
    PantherRuleTest(
        Name="No Domain",
        ExpectedResult=False,
        Log={
            "ContextProcessId": "440890253753908704",
            "ContextThreadId": "0",
            "ContextTimeStamp": "2022-08-31 07:03:48.879",
            "EffectiveTransmissionClass": 2,
            "Entitlements": "15",
            "RequestType": "1",
            "event_platform": "Mac",
            "event_simpleName": "DnsRequest",
            "name": "DnsRequestMacV2",
            "p_any_domain_names": [],
            "timestamp": "2022-08-31 07:03:49.195",
        },
    ),
    PantherRuleTest(
        Name="Known good and malicious domain",
        ExpectedResult=True,
        Log={
            "ContextProcessId": "440890253753908704",
            "ContextThreadId": "0",
            "ContextTimeStamp": "2022-08-31 07:03:48.879",
            "EffectiveTransmissionClass": 2,
            "Entitlements": "15",
            "RequestType": "1",
            "event_platform": "Mac",
            "event_simpleName": "DnsRequest",
            "name": "DnsRequestMacV2",
            "p_any_domain_names": ["company_name_here.okta.com", "company_name_here-maokta.com"],
            "timestamp": "2022-08-31 07:03:49.195",
        },
    ),
    PantherRuleTest(
        Name="Known good and malicious domain with Crowdstrike.FDREvent",
        ExpectedResult=True,
        Log={
            "event_simpleName": "DnsRequest",
            "name": "DnsRequestMacV1",
            "aid": "00000000000000000000000000000001",
            "aip": "111.111.111.111",
            "cid": "00000000000000000000000000000002",
            "id": "11111111-0000-1111-0000-111111111111",
            "event": {
                "aid": "00000000000000000000000000000001",
                "event_simpleName": "DnsRequest",
                "name": "DnsRequestMacV1",
                "aip": "111.111.111.111",
                "cid": "00000000000000000000000000000002",
                "id": "11111111-0000-1111-0000-111111111111",
                "event_platform": "Mac",
                "timestamp": "2021-10-01 00:00:00.000Z",
                "ConfigBuild": "1007.4.0014301.11",
                "ConfigStateHash": "507116305",
                "Entitlements": "15",
                "ContextThreadId": "0",
                "ContextTimeStamp": "2021-10-08 19:55:04.448Z",
                "ContextProcessId": "111111111111111111",
                "EffectiveTransmissionClass": 2,
                "DomainName": "gooddomain.com",
                "RequestType": "1",
            },
            "event_platform": "Mac",
            "fdr_event_type": "DnsRequest",
            "timestamp": "2021-10-01 00:00:00.000Z",
            "ConfigBuild": "1007.4.0014301.11",
            "ConfigStateHash": "507116305",
            "Entitlements": "15",
            "ContextThreadId": "0",
            "ContextTimeStamp": "2021-10-08 19:55:04.448Z",
            "ContextProcessId": "111111111111111111",
            "EffectiveTransmissionClass": 2,
            "RequestType": "1",
            "p_event_time": "2021-10-08 19:55:04.448Z",
            "p_parse_time": "2021-10-08 20:09:41.933Z",
            "p_log_type": "Crowdstrike.FDREvent",
            "p_row_id": "2ed00000000000000000000000000001",
            "p_source_id": "11111111-1111-1111-1111-111111111111",
            "p_source_label": "Crowdstrike",
            "p_any_ip_addresses": ["111.111.111.111"],
            "p_any_domain_names": ["company_name_here.okta.com", "company_name_here-maokta.com"],
            "p_any_trace_ids": [
                "00000000000000000000000000000001",
                "00000000000000000000000000000002",
            ],
        },
    ),
    PantherRuleTest(
        Name="non DnsRequest Crowdstrike.FDREvent event",
        ExpectedResult=False,
        Log={
            "event_simpleName": "something else",
            "event": {
                "aid": "00000000000000000000000000000001",
                "event_simpleName": "something else",
                "ContextTimeStamp": "2021-10-08 19:55:04.448Z",
                "ContextProcessId": "111111111111111111",
                "EffectiveTransmissionClass": 2,
                "DomainName": "gooddomain.com",
                "RequestType": "1",
            },
            "event_platform": "Mac",
            "fdr_event_type": "something else",
            "ContextProcessId": "111111111111111111",
            "EffectiveTransmissionClass": 2,
            "RequestType": "1",
            "p_event_time": "2021-10-08 19:55:04.448Z",
            "p_parse_time": "2021-10-08 20:09:41.933Z",
            "p_log_type": "Crowdstrike.FDREvent",
            "p_row_id": "2ed00000000000000000000000000001",
            "p_source_id": "11111111-1111-1111-1111-111111111111",
            "p_source_label": "Crowdstrike",
            "p_any_ip_addresses": ["111.111.111.111"],
            "p_any_domain_names": ["company_name_here.okta.com", "company_name_here-maokta.com"],
            "p_any_trace_ids": [
                "00000000000000000000000000000001",
                "00000000000000000000000000000002",
            ],
        },
    ),
]


class StandardMaliciousSSODNSLookup(PantherRule):
    RuleID = "Standard.MaliciousSSODNSLookup-prototype"
    DedupPeriodMinutes = 1440
    DisplayName = "Malicious SSO DNS Lookup"
    Enabled = False
    LogTypes = [
        LogType.CiscoUmbrella_DNS,
        LogType.Crowdstrike_DNSRequest,
        LogType.Crowdstrike_FDREvent,
        LogType.Suricata_DNS,
        LogType.Zeek_DNS,
    ]
    Severity = PantherSeverity.Medium
    Threshold = 1000
    Tags = ["Configuration Required"]
    Reports = {"MITRE ATT&CK": ["TA0001:T1566"]}
    Description = "The rule looks for DNS requests to sites potentially posing as SSO domains."
    Runbook = "Verify if the destination domain is owned by your organization."
    Reference = "https://www.cloudns.net/wiki/article/254/#:~:text=A%20DNS%20query%20(also%20known,associated%20with%20a%20domain%20name"
    SummaryAttributes = ["p_any_ip_addresses"]
    Tests = standard_malicious_ssodns_lookup_tests
    '\nWe highly recommend running this logic over 30 days of historical data using data replay\nbefore enabling this in your Panther instance. If ALLOWED_DOMAINS is not fully populated with\ndomains you own, that contain your company name, false positive alerts will be generated.\n\nRecommended steps to enable:\n    1. Change COMPANY_NAME to match your organization\n    2. Update the occurrences of "company_name_here" in malicious_sso_dns_lookup.yml\n    3. Add known domains containing COMPANY_NAME to ALLOWED_DOMAINS\n    4. Run local tests\n    5. Run a Data Replay test to identify unknown domains that should be in ALLOWED_DOMAINS\n'
    # *** Change this to match your company name ***
    COMPANY_NAME = "company_name_here"
    # Ref: https://blog.group-ib.com/0ktapus
    FAKE_KEYWORDS = ["sso", "okta", "corp", "vpn", "citrix", "help", "edge"]
    # Add known good domains that contain your company name
    #   "COMPANY.com",
    ALLOWED_DOMAINS = [".amazonaws.com", ".okta.com", ".oktapreview.com"]

    def rule(self, event):
        # We need to run either for Crowdstrike.DnsRequest or for DnsRequest.FDREvent of 'DnsRequest'
        # type. Crowdstrike.DnsRequest is covered because of the association with the type
        if filter_crowdstrike_fdr_event_type(event, "DnsRequest"):
            return False
        # check domain for company name AND a fake keyword
        for domain in event.get("p_any_domain_names", []):
            domain_was_allowed = [x for x in self.ALLOWED_DOMAINS if domain.lower().endswith(x)]
            if domain_was_allowed:
                continue
            if self.COMPANY_NAME in domain.lower():
                fake_matches = [x for x in self.FAKE_KEYWORDS if x in domain.lower()]
                if fake_matches:
                    return True
        # The domain did not have a fake keyword and the company name
        return False

    def title(self, event):
        return f"Potential Malicious SSO Domain - {event.get('p_any_domain_names', '')[0]}"
