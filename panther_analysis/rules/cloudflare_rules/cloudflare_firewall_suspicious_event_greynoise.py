from ipaddress import ip_address
from typing import List

from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_cloudflare_helpers import cloudflare_fw_alert_context
from panther_analysis.helpers.panther_greynoise_helpers import (
    GetGreyNoiseObject,
    GetGreyNoiseRiotObject,
)

cloudflare_firewall_suspicious_event_grey_noise_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Blocked Event - Malicious",
        ExpectedResult=False,
        Log={
            "Action": "block",
            "ClientASN": 14061,
            "ClientASNDescription": "DIGITALOCEAN-ASN",
            "ClientCountry": "nl",
            "ClientIP": "142.93.204.250",
            "ClientIPClass": "noRecord",
            "ClientRefererHost": "www.example.com",
            "ClientRefererPath": "/Visitor/bin/WebStrings.srf",
            "ClientRefererQuery": "?file=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows/win.ini&obj_name=aaa",
            "ClientRefererScheme": "https",
            "ClientRequestHost": "example.com",
            "ClientRequestMethod": "GET",
            "ClientRequestPath": "/Visitor/bin/WebStrings.srf",
            "ClientRequestProtocol": "HTTP/1.1",
            "ClientRequestQuery": "?file=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows/win.ini&obj_name=aaa",
            "ClientRequestScheme": "https",
            "ClientRequestUserAgent": "Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36",
            "Datetime": "2022-05-08 10:19:15",
            "EdgeColoCode": "AMS",
            "EdgeResponseStatus": 403,
            "Kind": "firewall",
            "MatchIndex": 0,
            "Metadata": {"ruleset_version": "65", "type": "customer", "version": "59"},
            "OriginResponseStatus": 0,
            "OriginatorRayID": "00",
            "RayID": "708174c00f61faa8",
            "RuleID": "e35c9a670b864a3ba0203ffb1bc977d1",
            "Source": "firewallmanaged",
            "p_enrichment": {
                "greynoise_noise_basic": {
                    "ClientIP": {
                        "actor": "unknown",
                        "bot": False,
                        "classification": "malicious",
                        "cve": [],
                        "first_seen": "2022-03-19",
                        "ip": "142.93.204.250",
                        "last_seen": "2022-04-06",
                        "metadata": {
                            "asn": "AS14061",
                            "category": "hosting",
                            "city": "North Bergen",
                            "country": "United States",
                            "country_code": "US",
                            "organization": "DigitalOcean, LLC",
                            "os": "Linux 2.2-3.x",
                            "rdns": "",
                            "region": "New Jersey",
                            "tor": False,
                        },
                        "raw_data": {
                            "hassh": [],
                            "ja3": [],
                            "scan": [{"port": 23, "protocol": "TCP"}],
                            "web": {},
                        },
                        "seen": True,
                        "spoofable": False,
                        "tags": ["Mirai", "ZMap Client"],
                        "vpn": False,
                        "vpn_service": "N/A",
                    }
                }
            },
        },
    ),
    PantherRuleTest(
        Name="Skip Event - Non-Malicious",
        ExpectedResult=False,
        Log={
            "Action": "skip",
            "ClientASN": 14061,
            "ClientASNDescription": "DIGITALOCEAN-ASN",
            "ClientCountry": "nl",
            "ClientIP": "127.0.0.1",
            "ClientIPClass": "noRecord",
            "ClientRefererHost": "www.example.com",
            "ClientRefererPath": "/Visitor/bin/WebStrings.srf",
            "ClientRefererQuery": "?file=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows/win.ini&obj_name=aaa",
            "ClientRefererScheme": "https",
            "ClientRequestHost": "example.com",
            "ClientRequestMethod": "GET",
            "ClientRequestPath": "/Visitor/bin/WebStrings.srf",
            "ClientRequestProtocol": "HTTP/1.1",
            "ClientRequestQuery": "?file=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows/win.ini&obj_name=aaa",
            "ClientRequestScheme": "https",
            "ClientRequestUserAgent": "Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36",
            "Datetime": "2022-05-08 10:19:15",
            "EdgeColoCode": "AMS",
            "EdgeResponseStatus": 403,
            "Kind": "firewall",
            "MatchIndex": 0,
            "Metadata": {"ruleset_version": "65", "type": "customer", "version": "59"},
            "OriginResponseStatus": 0,
            "OriginatorRayID": "00",
            "RayID": "708174c00f61faa8",
            "RuleID": "e35c9a670b864a3ba0203ffb1bc977d1",
            "Source": "firewallmanaged",
            "p_enrichment": {
                "greynoise_noise_basic": {
                    "ClientIP": {
                        "actor": "unknown",
                        "bot": False,
                        "classification": "benign",
                        "cve": [],
                        "first_seen": "2022-03-19",
                        "ip": "142.93.204.250",
                        "last_seen": "2022-04-06",
                        "metadata": {
                            "asn": "AS14061",
                            "category": "hosting",
                            "city": "North Bergen",
                            "country": "United States",
                            "country_code": "US",
                            "organization": "DigitalOcean, LLC",
                            "os": "Linux 2.2-3.x",
                            "rdns": "",
                            "region": "New Jersey",
                            "tor": False,
                        },
                        "raw_data": {
                            "hassh": [],
                            "ja3": [],
                            "scan": [{"port": 23, "protocol": "TCP"}],
                            "web": {},
                        },
                        "seen": True,
                        "spoofable": False,
                        "tags": [],
                        "vpn": False,
                        "vpn_service": "N/A",
                    }
                }
            },
        },
    ),
    PantherRuleTest(
        Name="Skip Event - Malicious",
        ExpectedResult=True,
        Log={
            "Action": "skip",
            "ClientASN": 14061,
            "ClientASNDescription": "DIGITALOCEAN-ASN",
            "ClientCountry": "nl",
            "ClientIP": "142.93.204.250",
            "ClientIPClass": "noRecord",
            "ClientRefererHost": "www.example.com",
            "ClientRefererPath": "/Visitor/bin/WebStrings.srf",
            "ClientRefererQuery": "?file=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows/win.ini&obj_name=aaa",
            "ClientRefererScheme": "https",
            "ClientRequestHost": "example.com",
            "ClientRequestMethod": "GET",
            "ClientRequestPath": "/Visitor/bin/WebStrings.srf",
            "ClientRequestProtocol": "HTTP/1.1",
            "ClientRequestQuery": "?file=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows/win.ini&obj_name=aaa",
            "ClientRequestScheme": "https",
            "ClientRequestUserAgent": "Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36",
            "Datetime": "2022-05-08 10:19:15",
            "EdgeColoCode": "AMS",
            "EdgeResponseStatus": 403,
            "Kind": "firewall",
            "MatchIndex": 0,
            "Metadata": {"ruleset_version": "65", "type": "customer", "version": "59"},
            "OriginResponseStatus": 0,
            "OriginatorRayID": "00",
            "RayID": "708174c00f61faa8",
            "RuleID": "e35c9a670b864a3ba0203ffb1bc977d1",
            "Source": "firewallmanaged",
            "p_enrichment": {
                "greynoise_noise_basic": {
                    "ClientIP": {
                        "actor": "unknown",
                        "bot": False,
                        "classification": "malicious",
                        "cve": [],
                        "first_seen": "2022-03-19",
                        "ip": "142.93.204.250",
                        "last_seen": "2022-04-06",
                        "metadata": {
                            "asn": "AS14061",
                            "category": "hosting",
                            "city": "North Bergen",
                            "country": "United States",
                            "country_code": "US",
                            "organization": "DigitalOcean, LLC",
                            "os": "Linux 2.2-3.x",
                            "rdns": "",
                            "region": "New Jersey",
                            "tor": False,
                        },
                        "raw_data": {
                            "hassh": [],
                            "ja3": [],
                            "scan": [{"port": 23, "protocol": "TCP"}],
                            "web": {},
                        },
                        "seen": True,
                        "spoofable": False,
                        "tags": ["Mirai", "ZMap Client"],
                        "vpn": False,
                        "vpn_service": "N/A",
                    }
                }
            },
        },
    ),
]


class CloudflareFirewallSuspiciousEventGreyNoise(PantherRule):
    RuleID = "Cloudflare.Firewall.SuspiciousEventGreyNoise-prototype"
    DisplayName = "--DEPRECATED-- Cloudflare Suspicious Event - GreyNoise"
    Enabled = False
    LogTypes = ["Cloudflare.Firewall"]
    Tags = ["Cloudflare", "GreyNoise", "Deprecated"]
    Severity = Severity.Medium
    Description = (
        "Monitors for non-blocked requests from Greynoise identified malicious IP Addresses"
    )
    Runbook = "Inspect resources accessed for malicious behavior"
    Reference = "https://docs.greynoise.io/docs/understanding-greynoise-enrichments"
    SummaryAttributes = [
        "ClientRequestUserAgent",
        "ClientRequestPath",
        "ClientRequestQuery",
        "Action",
        "EdgeResponseStatus",
        "OriginResponseStatus",
        "Source",
    ]
    Tests = cloudflare_firewall_suspicious_event_grey_noise_tests

    def rule(self, event):
        if event.get("Action") == "block":
            return False
        # Validate the IP is actually an IP
        try:
            ip_address(event.get("ClientIP"))
        except ValueError:
            return False
        # Setup GreyNoise variables
        self.NOISE = GetGreyNoiseObject(event)
        riot = GetGreyNoiseRiotObject(event)
        # If IP is in the RIOT dataset, we can assume it is safe
        if riot.is_riot("ClientIP"):
            return False
        # Check if IP classified as malicious
        return self.NOISE.classification("ClientIP") == "malicious"

    def title(self, event):
        return f"Cloudflare: Non-blocked requests - Greynoise malicious IP -from [{event.get('ClientIP', '<NO_CLIENTIP>')}] to [{event.get('ClientRequestHost', '<NO_REQ_HOST>')}]"

    def dedup(self, event):
        return f"{event.get('ClientIP', '<NO_CLIENTIP>')}:{event.get('ClientRequestHost', '<NO_REQ_HOST>')}"

    def alert_context(self, event):
        ctx = cloudflare_fw_alert_context(event)
        ctx["GreyNoise"] = self.NOISE.context("ClientIP")
        return ctx
