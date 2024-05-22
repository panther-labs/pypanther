from typing import List
from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from ipaddress import ip_address
from panther_analysis.helpers.panther_cloudflare_helpers import cloudflare_http_alert_context
from panther_analysis.helpers.panther_greynoise_helpers import (
    GetGreyNoiseObject,
    GetGreyNoiseRiotObject,
)

cloudflare_http_request_bot_high_volume_grey_noise_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Likely Human",
        ExpectedResult=False,
        Log={
            "BotScore": 99,
            "CacheCacheStatus": "miss",
            "CacheResponseBytes": 76931,
            "CacheResponseStatus": 404,
            "CacheTieredFill": False,
            "ClientASN": 63949,
            "ClientCountry": "gb",
            "ClientDeviceType": "desktop",
            "ClientIP": "142.93.204.250",
            "ClientIPClass": "noRecord",
            "ClientRequestBytes": 2407,
            "ClientRequestHost": "example.com",
            "ClientRequestMethod": "GET",
            "ClientRequestPath": "",
            "ClientRequestProtocol": "HTTP/1.1",
            "ClientRequestReferer": "https://example.com/",
            "ClientRequestURI": "",
            "ClientRequestUserAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "ClientSSLProtocol": "TLSv1.3",
            "ClientSrcPort": 28057,
            "ClientXRequestedWith": "",
            "EdgeColoCode": "LHR",
            "EdgeColoID": 373,
            "EdgeEndTimestamp": "2022-05-07 18:53:13",
            "EdgePathingOp": "wl",
            "EdgePathingSrc": "macro",
            "EdgePathingStatus": "nr",
            "EdgeRateLimitAction": "",
            "EdgeRateLimitID": "0",
            "EdgeRequestHost": "example.com",
            "EdgeResponseBytes": 17826,
            "EdgeResponseCompressionRatio": 4.55,
            "EdgeResponseContentType": "text/html",
            "EdgeResponseStatus": 404,
            "EdgeServerIP": "",
            "EdgeStartTimestamp": "2022-05-07 18:53:12",
            "OriginIP": "",
            "OriginResponseBytes": 0,
            "OriginResponseStatus": 0,
            "OriginResponseTime": 0,
            "OriginSSLProtocol": "unknown",
            "ParentRayID": "00",
            "RayID": "707c283ab88274cd",
            "SecurityLevel": "med",
            "WAFAction": "unknown",
            "WAFFlags": "0",
            "WAFMatchedVar": "",
            "WAFProfile": "unknown",
            "WAFRuleID": "",
            "WAFRuleMessage": "",
            "WorkerCPUTime": 0,
            "WorkerStatus": "unknown",
            "WorkerSubrequest": False,
            "WorkerSubrequestCount": 0,
            "ZoneID": 526503649,
            "p_any_domain_names": ["https://example.com/", "example.com"],
            "p_any_ip_addresses": ["142.93.204.250"],
            "p_any_trace_ids": ["00", "707c283ab88274cd"],
            "p_event_time": "2022-05-07 18:53:12",
            "p_log_type": "Cloudflare.HttpRequest",
            "p_parse_time": "2022-05-07 18:54:31.922",
            "p_row_id": "a6e3965df054cfcdbdccf3ec10a134",
            "p_source_id": "2b9fc5ae-9cab-4715-8683-9bfbdb15a313",
            "p_source_label": "Cloudflare",
        },
    ),
    PantherRuleTest(
        Name="Likely Automated",
        ExpectedResult=True,
        Log={
            "BotScore": 29,
            "CacheCacheStatus": "miss",
            "CacheResponseBytes": 76931,
            "CacheResponseStatus": 404,
            "CacheTieredFill": False,
            "ClientASN": 63949,
            "ClientCountry": "gb",
            "ClientDeviceType": "desktop",
            "ClientIP": "142.93.204.250",
            "ClientIPClass": "noRecord",
            "ClientRequestBytes": 2407,
            "ClientRequestHost": "example.com",
            "ClientRequestMethod": "GET",
            "ClientRequestPath": "",
            "ClientRequestProtocol": "HTTP/1.1",
            "ClientRequestReferer": "https://example.com/",
            "ClientRequestURI": "",
            "ClientRequestUserAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "ClientSSLProtocol": "TLSv1.3",
            "ClientSrcPort": 28057,
            "ClientXRequestedWith": "",
            "EdgeColoCode": "LHR",
            "EdgeColoID": 373,
            "EdgeEndTimestamp": "2022-05-07 18:53:13",
            "EdgePathingOp": "wl",
            "EdgePathingSrc": "macro",
            "EdgePathingStatus": "nr",
            "EdgeRateLimitAction": "",
            "EdgeRateLimitID": "0",
            "EdgeRequestHost": "example.com",
            "EdgeResponseBytes": 17826,
            "EdgeResponseCompressionRatio": 4.55,
            "EdgeResponseContentType": "text/html",
            "EdgeResponseStatus": 404,
            "EdgeServerIP": "",
            "EdgeStartTimestamp": "2022-05-07 18:53:12",
            "OriginIP": "",
            "OriginResponseBytes": 0,
            "OriginResponseStatus": 0,
            "OriginResponseTime": 0,
            "OriginSSLProtocol": "unknown",
            "ParentRayID": "00",
            "RayID": "707c283ab88274cd",
            "SecurityLevel": "med",
            "WAFAction": "unknown",
            "WAFFlags": "0",
            "WAFMatchedVar": "",
            "WAFProfile": "unknown",
            "WAFRuleID": "",
            "WAFRuleMessage": "",
            "WorkerCPUTime": 0,
            "WorkerStatus": "unknown",
            "WorkerSubrequest": False,
            "WorkerSubrequestCount": 0,
            "ZoneID": 526503649,
            "p_any_domain_names": ["https://example.com/", "example.com"],
            "p_any_ip_addresses": ["142.93.204.250"],
            "p_any_trace_ids": ["00", "707c283ab88274cd"],
            "p_event_time": "2022-05-07 18:53:12",
            "p_log_type": "Cloudflare.HttpRequest",
            "p_parse_time": "2022-05-07 18:54:31.922",
            "p_row_id": "a6e3965df054cfcdbdccf3ec10a134",
            "p_source_id": "2b9fc5ae-9cab-4715-8683-9bfbdb15a313",
            "p_source_label": "Cloudflare",
        },
    ),
    PantherRuleTest(
        Name="Likely Automated - B2B",
        ExpectedResult=False,
        Log={
            "BotScore": 29,
            "CacheCacheStatus": "miss",
            "CacheResponseBytes": 76931,
            "CacheResponseStatus": 404,
            "CacheTieredFill": False,
            "ClientASN": 63949,
            "ClientCountry": "gb",
            "ClientDeviceType": "desktop",
            "ClientIP": "142.93.204.250",
            "ClientIPClass": "noRecord",
            "ClientRequestBytes": 2407,
            "ClientRequestHost": "example.com",
            "ClientRequestMethod": "GET",
            "ClientRequestPath": "",
            "ClientRequestProtocol": "HTTP/1.1",
            "ClientRequestReferer": "https://example.com/",
            "ClientRequestURI": "",
            "ClientRequestUserAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "ClientSSLProtocol": "TLSv1.3",
            "ClientSrcPort": 28057,
            "ClientXRequestedWith": "",
            "EdgeColoCode": "LHR",
            "EdgeColoID": 373,
            "EdgeEndTimestamp": "2022-05-07 18:53:13",
            "EdgePathingOp": "wl",
            "EdgePathingSrc": "macro",
            "EdgePathingStatus": "nr",
            "EdgeRateLimitAction": "",
            "EdgeRateLimitID": "0",
            "EdgeRequestHost": "example.com",
            "EdgeResponseBytes": 17826,
            "EdgeResponseCompressionRatio": 4.55,
            "EdgeResponseContentType": "text/html",
            "EdgeResponseStatus": 404,
            "EdgeServerIP": "",
            "EdgeStartTimestamp": "2022-05-07 18:53:12",
            "OriginIP": "",
            "OriginResponseBytes": 0,
            "OriginResponseStatus": 0,
            "OriginResponseTime": 0,
            "OriginSSLProtocol": "unknown",
            "ParentRayID": "00",
            "RayID": "707c283ab88274cd",
            "SecurityLevel": "med",
            "WAFAction": "unknown",
            "WAFFlags": "0",
            "WAFMatchedVar": "",
            "WAFProfile": "unknown",
            "WAFRuleID": "",
            "WAFRuleMessage": "",
            "WorkerCPUTime": 0,
            "WorkerStatus": "unknown",
            "WorkerSubrequest": False,
            "WorkerSubrequestCount": 0,
            "ZoneID": 526503649,
            "p_any_domain_names": ["https://example.com/", "example.com"],
            "p_any_ip_addresses": ["142.93.204.250"],
            "p_any_trace_ids": ["00", "707c283ab88274cd"],
            "p_event_time": "2022-05-07 18:53:12",
            "p_log_type": "Cloudflare.HttpRequest",
            "p_parse_time": "2022-05-07 18:54:31.922",
            "p_row_id": "a6e3965df054cfcdbdccf3ec10a134",
            "p_source_id": "2b9fc5ae-9cab-4715-8683-9bfbdb15a313",
            "p_source_label": "Cloudflare",
            "p_enrichment": {
                "greynoise_riot_basic": {
                    "ClientIP": {
                        "ip_address": "142.93.204.250",
                        "is_riot": True,
                        "ip_cidr": "142.93.204.250/32",
                    }
                }
            },
        },
    ),
    PantherRuleTest(
        Name="Bot Score Not Computed",
        ExpectedResult=False,
        Log={
            "BotScore": 0,
            "CacheCacheStatus": "miss",
            "CacheResponseBytes": 76931,
            "CacheResponseStatus": 404,
            "CacheTieredFill": False,
            "ClientASN": 63949,
            "ClientCountry": "gb",
            "ClientDeviceType": "desktop",
            "ClientIP": "142.93.204.250",
            "ClientIPClass": "noRecord",
            "ClientRequestBytes": 2407,
            "ClientRequestHost": "example.com",
            "ClientRequestMethod": "GET",
            "ClientRequestPath": "",
            "ClientRequestProtocol": "HTTP/1.1",
            "ClientRequestReferer": "https://example.com/",
            "ClientRequestURI": "",
            "ClientRequestUserAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "ClientSSLProtocol": "TLSv1.3",
            "ClientSrcPort": 28057,
            "ClientXRequestedWith": "",
            "EdgeColoCode": "LHR",
            "EdgeColoID": 373,
            "EdgeEndTimestamp": "2022-05-07 18:53:13",
            "EdgePathingOp": "wl",
            "EdgePathingSrc": "macro",
            "EdgePathingStatus": "nr",
            "EdgeRateLimitAction": "",
            "EdgeRateLimitID": "0",
            "EdgeRequestHost": "example.com",
            "EdgeResponseBytes": 17826,
            "EdgeResponseCompressionRatio": 4.55,
            "EdgeResponseContentType": "text/html",
            "EdgeResponseStatus": 404,
            "EdgeServerIP": "",
            "EdgeStartTimestamp": "2022-05-07 18:53:12",
            "OriginIP": "",
            "OriginResponseBytes": 0,
            "OriginResponseStatus": 0,
            "OriginResponseTime": 0,
            "OriginSSLProtocol": "unknown",
            "ParentRayID": "00",
            "RayID": "707c283ab88274cd",
            "SecurityLevel": "med",
            "WAFAction": "unknown",
            "WAFFlags": "0",
            "WAFMatchedVar": "",
            "WAFProfile": "unknown",
            "WAFRuleID": "",
            "WAFRuleMessage": "",
            "WorkerCPUTime": 0,
            "WorkerStatus": "unknown",
            "WorkerSubrequest": False,
            "WorkerSubrequestCount": 0,
            "ZoneID": 526503649,
            "p_any_domain_names": ["https://example.com/", "example.com"],
            "p_any_ip_addresses": ["142.93.204.250"],
            "p_any_trace_ids": ["00", "707c283ab88274cd"],
            "p_event_time": "2022-05-07 18:53:12",
            "p_log_type": "Cloudflare.HttpRequest",
            "p_parse_time": "2022-05-07 18:54:31.922",
            "p_row_id": "a6e3965df054cfcdbdccf3ec10a134",
            "p_source_id": "2b9fc5ae-9cab-4715-8683-9bfbdb15a313",
            "p_source_label": "Cloudflare",
        },
    ),
]


class CloudflareHttpRequestBotHighVolumeGreyNoise(PantherRule):
    RuleID = "Cloudflare.HttpRequest.BotHighVolumeGreyNoise-prototype"
    DisplayName = "--DEPRECATED-- Cloudflare Bot High Volume GreyNoise"
    Enabled = False
    LogTypes = ["Cloudflare.HttpRequest"]
    Tags = ["Cloudflare", "GreyNoise", "Deprecated"]
    Severity = Severity.Low
    Description = (
        "Monitors for high volume of likely automated HTTP Requests with GreyNoise enrichment"
    )
    Runbook = "Inspect and monitor internet-facing services for potential outages"
    Reference = "https://docs.greynoise.io/docs/understanding-greynoise-enrichments"
    DedupPeriodMinutes = 60
    Threshold = 7560
    SummaryAttributes = [
        "ClientIP",
        "ClientRequestUserAgent",
        "EdgeResponseContentType",
        "ClientCountry",
        "ClientRequestURI",
    ]
    Tests = cloudflare_http_request_bot_high_volume_grey_noise_tests

    def rule(self, event):
        # Bot scores are [0, 99] where scores >=1 && <30 indicating likely automated
        # https://developers.cloudflare.com/bots/concepts/bot-score/
        if not all([event.get("BotScore", 100) <= 30, event.get("BotScore", 100) >= 1]):
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
        return True

    def title(self, event):
        return f"Cloudflare: High Volume of Bot Requests - GreyNoise non-RIOT - from [{event.get('ClientIP', '<NO_CLIENTIP>')}] to [{event.get('ClientRequestHost', '<NO_REQ_HOST>')}]"

    def dedup(self, event):
        return f"{event.get('ClientIP', '<NO_CLIENTIP>')}:{event.get('ClientRequestHost', '<NO_REQ_HOST>')}"

    def alert_context(self, event):
        ctx = cloudflare_http_alert_context(event)
        ctx["GreyNoise"] = self.NOISE.context("ClientIP")
        return ctx
