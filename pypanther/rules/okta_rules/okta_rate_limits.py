from fnmatch import fnmatch

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import okta_alert_context

okta_rate_limits_tests: list[RuleTest] = [
    RuleTest(
        name="system.org.ratelimit.warning",
        expected_result=True,
        log={
            "actor": {
                "alternateId": "homer.simpson@duff.com",
                "displayName": "Homer Simpson",
                "id": "00abc456",
                "type": "User",
            },
            "authenticationcontext": {"authenticationStep": 0, "externalSessionId": "abc12345"},
            "client": {
                "device": "Unknown",
                "ipAddress": "1.2.3.4",
                "userAgent": {"browser": "UNKNOWN", "os": "Unknown", "rawUserAgent": "Chrome"},
                "zone": "null",
            },
            "debugcontext": {
                "debugData": {
                    "rateLimitScopeType": "ORG",
                    "rateLimitSecondsToReset": "11",
                    "requestId": "abc1234",
                    "requestUri": "/api/v1/users",
                    "threshold": "500",
                    "timeSpan": "1",
                    "timeUnit": "MINUTES",
                    "url": "/api/v1/users?limit=100",
                    "userId": "abc1234",
                    "warningPercent": "80",
                },
            },
            "displaymessage": "Rate limit warning",
            "eventtype": "system.org.rate_limit.warning",
            "legacyeventtype": "core.framework.ratelimit.warning",
            "outcome": {"result": "SUCCESS"},
            "published": "2022-08-26 07:51:24.601",
            "request": {"ipChain": [{"ip": "1.2.3.4", "version": "V4"}]},
            "securitycontext": {},
            "severity": "INFO",
            "target": [{"id": "/api/v1/users", "type": "URL Pattern"}, {"id": "abc12345", "type": "Bucket Uuid"}],
            "transaction": {"detail": {"requestApiTokenId": "A.12345.DEFGH"}, "id": "ABC1235", "type": "WEB"},
            "uuid": "abc-1234-abcd",
            "version": "0",
        },
    ),
    RuleTest(
        name="system.operation.ratelimit.violation",
        expected_result=True,
        log={
            "actor": {
                "alternateId": "homer.simpson@duff.com",
                "displayName": "Homer Simpson",
                "id": "00abc456",
                "type": "User",
            },
            "authenticationcontext": {"authenticationStep": 0, "externalSessionId": "abc12345"},
            "client": {
                "device": "Unknown",
                "ipAddress": "1.2.3.4",
                "userAgent": {"browser": "UNKNOWN", "os": "Unknown", "rawUserAgent": "Chrome"},
                "zone": "null",
            },
            "debugcontext": {
                "debugData": {
                    "authnRequestId": "ABCDFDE",
                    "dtHash": "adfalsjflasfjsdfd",
                    "operationRateLimitScopeType": "User",
                    "operationRateLimitSecondsToReset": "10",
                    "operationRateLimitSubtype": "Authenticated user",
                    "operationRateLimitThreshold": "40",
                    "operationRateLimitTimeSpan": "10",
                    "operationRateLimitTimeUnit": "SECONDS",
                    "operationRateLimitType": "Web request",
                    "requestId": "asfsagadffdaf",
                    "requestUri": "/app/google/",
                    "url": "/app/google/",
                },
            },
            "displaymessage": "Operation rate limit violation",
            "eventtype": "system.operation.rate_limit.violation",
            "outcome": {"reason": "Too many requests attempted by an individual user", "result": "DENY"},
            "published": "2022-08-29 16:07:26.592",
            "request": {"ipChain": [{"ip": "1.2.3.4", "version": "V4"}]},
            "securitycontext": {},
            "severity": "WARN",
            "target": [{"id": "/app/{app}/{key}/", "type": "URL Pattern"}],
            "transaction": {"detail": {}, "id": "YABCDE", "type": "WEB"},
            "uuid": "asdfdashh",
            "version": "0",
        },
    ),
    RuleTest(
        name="application.integration.rate_limit_exceeded",
        expected_result=True,
        log={
            "actor": {
                "alternateId": "homer.simpson@duff.com",
                "displayName": "Homer Simpson",
                "id": "00abc456",
                "type": "User",
            },
            "authenticationcontext": {"authenticationStep": 0, "externalSessionId": "abc12345"},
            "client": {
                "device": "Unknown",
                "ipAddress": "1.2.3.4",
                "userAgent": {"browser": "UNKNOWN", "os": "Unknown", "rawUserAgent": "Chrome"},
                "zone": "null",
            },
            "debugcontext": {"debugData": {}},
            "eventtype": "application.integration.rate_limit_exceeded",
            "legacyeventtype": "app.api.error.rate.limit.exceeded",
            "outcome": {"result": "SUCCESS"},
            "published": "2022-06-10 17:19:58.423",
            "request": {},
            "securitycontext": {},
            "severity": "INFO",
            "target": [{"alternateId": "App ", "displayName": "App", "id": "12345", "type": "AppInstance"}],
            "transaction": {"detail": {}, "id": "sdfg", "type": "JOB"},
            "uuid": "aaa-bb-ccc",
            "version": "0",
        },
    ),
    RuleTest(
        name="Non event",
        expected_result=False,
        log={
            "actor": {
                "alternateId": "homer.simpson@duff.com",
                "displayName": "Homer Simpsons",
                "id": "00ABC123",
                "type": "User",
            },
            "authenticationcontext": {"authenticationStep": 0, "externalSessionId": "xyz1234"},
            "client": {
                "device": "Computer",
                "geographicalContext": {
                    "city": "Springfield",
                    "country": "United States",
                    "geolocation": {"lat": 11.111, "lon": -70},
                    "postalCode": "1234",
                    "state": "California",
                },
                "ipAddress": "1.2.3.4",
                "userAgent": {
                    "browser": "CHROME",
                    "os": "Mac OS X",
                    "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
                },
                "zone": "null",
            },
            "debugcontext": {
                "debugData": {
                    "authnRequestId": "ABC123",
                    "deviceFingerprint": "009988771ABC",
                    "dtHash": "123abc1234",
                    "requestId": "abc-111-adf",
                    "requestUri": "/idp/idx/identify",
                    "threatSuspected": "false",
                    "url": "/idp/idx/identify?",
                },
            },
            "displaymessage": "Group Privilege granted",
            "eventtype": "group.privilege.grant",
            "legacyeventtype": "group.privilege.grant",
            "outcome": {"result": "FAILURE"},
            "published": "2022-12-13 00:58:19.811",
            "request": {
                "ipChain": [
                    {
                        "geographicalContext": {
                            "city": "Springfield",
                            "country": "United States",
                            "geolocation": {"lat": 11.111, "lon": -70},
                            "postalCode": "1234",
                            "state": "California",
                        },
                        "ip": "1.2.3.4",
                        "version": "V4",
                    },
                ],
            },
            "securitycontext": {
                "asNumber": 11351,
                "asOrg": "charter communications inc",
                "domain": "rr.com",
                "isProxy": False,
                "isp": "charter communications inc",
            },
            "severity": "WARN",
            "target": [{"alternateId": "App (123)", "displayName": "App (123)", "id": "12345", "type": "AppInstance"}],
            "transaction": {"detail": {}, "id": "aaa-bbb-123", "type": "WEB"},
            "uuid": "aa-11-22-33-44-bb",
            "version": "0",
        },
    ),
]


@panther_managed
class OktaRateLimits(Rule):
    default_description = "Potential DoS/Bruteforce attack or hitting limits (system degradation)"
    display_name = "Okta Rate Limits"
    default_severity = Severity.HIGH
    tags = ["Credential Access", "Brute Force", "Impact", "Network Denial of Service"]
    reports = {"MITRE ATT&CK": ["TA0006:T1110", "TA0040:T1498"]}
    default_reference = "https://developer.okta.com/docs/reference/rl-system-log-events/"
    dedup_period_minutes = 360
    log_types = [LogType.OKTA_SYSTEM_LOG]
    id = "Okta.Rate.Limits-prototype"
    tests = okta_rate_limits_tests
    DETECTION_EVENTS = [
        "app.oauth2.client_id_rate_limit_warning",
        "application.integration.rate_limit_exceeded",
        "system.client.rate_limit.*",
        "system.client.concurrency_rate_limit.*",
        "system.operation.rate_limit.*",
        "system.org.rate_limit.*",
        "core.concurrency.org.limit.violation",
    ]

    def rule(self, event):
        eventtype = event.get("eventtype", "")
        for detection_event in self.DETECTION_EVENTS:
            if fnmatch(eventtype, detection_event):
                return True
        return False

    def title(self, event):
        return f"Okta Rate Limit Event: [{event.get('eventtype', '')}] by [{event.get('actor', {}).get('alternateId', '<id-not-found>')}]"

    def severity(self, event):
        if event.get("severity", "") == "INFO":
            return "INFO"
        eventtype = event.get("eventtype", "")
        if "notification" in eventtype:
            return "LOW"
        if "warning" in eventtype:
            return "MEDIUM"
        if "violation" in eventtype:
            return "HIGH"
        return "DEFAULT"

    def alert_context(self, event):
        return okta_alert_context(event)
