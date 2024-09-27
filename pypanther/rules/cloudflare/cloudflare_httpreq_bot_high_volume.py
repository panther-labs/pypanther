from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.cloudflare import cloudflare_http_alert_context


@panther_managed
class CloudflareHttpRequestBotHighVolume(Rule):
    id = "Cloudflare.HttpRequest.BotHighVolume-prototype"
    display_name = "Cloudflare Bot High Volume"
    enabled = False
    log_types = [LogType.CLOUDFLARE_HTTP_REQUEST]
    tags = ["Cloudflare"]
    default_severity = Severity.LOW
    default_description = "Monitors for bots making HTTP Requests at a rate higher than 2req/sec"
    default_runbook = "Inspect and monitor internet-facing services for potential outages"
    default_reference = "https://developers.cloudflare.com/waf/rate-limiting-rules/request-rate/"
    threshold = 7560
    summary_attributes = [
        "ClientIP",
        "ClientRequestUserAgent",
        "EdgeResponseContentType",
        "ClientCountry",
        "ClientRequestURI",
    ]

    def rule(self, event):
        # Bot scores are [0, 99] where scores >0 && <30 indicating likely automated
        # https://developers.cloudflare.com/bots/concepts/bot-score/
        return all([event.get("BotScore", 100) <= 30, event.get("BotScore", 100) >= 1])

    def title(self, event):
        return f"Cloudflare: High Volume of Bot Requests - from [{event.get('ClientIP', '<NO_CLIENTIP>')}] to [{event.get('ClientRequestHost', '<NO_REQ_HOST>')}]"

    def dedup(self, event):
        return f"{event.get('ClientIP', '<NO_CLIENTIP>')}:{event.get('ClientRequestHost', '<NO_REQ_HOST>')}"

    def alert_context(self, event):
        return cloudflare_http_alert_context(event)

    tests = [
        RuleTest(
            name="Likely Human",
            expected_result=False,
            log={
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
        RuleTest(
            name="Likely Automated",
            expected_result=True,
            log={
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
    ]
