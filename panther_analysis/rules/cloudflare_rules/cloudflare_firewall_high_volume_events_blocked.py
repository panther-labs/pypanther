from typing import List
from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_cloudflare_helpers import cloudflare_fw_alert_context

cloudflare_firewall_high_volume_events_blocked_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Blocked Event",
        ExpectedResult=True,
        Log={
            "Action": "block",
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
        },
    ),
    PantherRuleTest(
        Name="Skip Event",
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
        },
    ),
]


class CloudflareFirewallHighVolumeEventsBlocked(PantherRule):
    RuleID = "Cloudflare.Firewall.HighVolumeEventsBlocked-prototype"
    DisplayName = "--DEPRECATED-- Cloudflare - High Volume Events Blocked"
    Enabled = False
    LogTypes = ["Cloudflare.Firewall"]
    Tags = ["Cloudflare"]
    Severity = Severity.Low
    Description = "Monitors high volume events blocked from the same IP"
    Runbook = "Inspect and monitor internet-facing services for potential outages"
    Reference = "https://developers.cloudflare.com/firewall/cf-firewall-rules/actions/"
    DedupPeriodMinutes = 60
    Threshold = 200
    SummaryAttributes = [
        "ClientRequestUserAgent",
        "ClientRequestPath",
        "Action",
        "EdgeResponseStatus",
        "OriginResponseStatus",
    ]
    Tests = cloudflare_firewall_high_volume_events_blocked_tests

    def rule(self, event):
        return event.get("Action", "") == "block"

    def title(self, event):
        return f"Cloudflare: High Volume of Block Actions - from [{event.get('ClientIP', '<NO_CLIENTIP>')}] to [{event.get('ClientRequestHost', '<NO_REQ_HOST>')}] "

    def dedup(self, event):
        return f"{event.get('ClientIP', '<NO_CLIENTIP>')}:{event.get('ClientRequestHost', '<NO_REQ_HOST>')}"

    def alert_context(self, event):
        return cloudflare_fw_alert_context(event)
