from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

okta_login_without_push_marker_tests: list[RuleTest] = [
    RuleTest(
        name="Login with marker",
        expected_result=False,
        log={
            "actor": {
                "alternateId": "alice.beaver@company.com",
                "displayName": "Alice Beaver",
                "id": "00u99ped55av2JpGs5d7",
                "type": "User",
            },
            "authenticationContext": {"authenticationStep": 0, "externalSessionId": "trsxcsf59kYRG-GwAbWjw-PZA"},
            "client": {
                "device": "Unknown",
                "ipAddress": "11.22.33.44",
                "userAgent": {"browser": "UNKNOWN", "os": "Unknown", "rawUserAgent": "Go-http-client/2.0 PS_mxzqarw"},
                "zone": "null",
            },
            "debugContext": {
                "debugData": {
                    "dtHash": "53dd1a7513e0256eb13b9a47bb07ed61e8ca3d35fbdc36c909567a21a65a2b19",
                    "rateLimitBucketUuid": "b192d91c-b242-36da-9332-d97a5579f865",
                    "rateLimitScopeType": "ORG",
                    "rateLimitSecondsToReset": "6",
                    "requestId": "234cf34e0081e025e1fe14224464bbd6",
                    "requestUri": "/api/v1/logs",
                    "threshold": "20",
                    "timeSpan": "1",
                    "timeUnit": "MINUTES",
                    "url": "/api/v1/logs?since=2023-09-21T17%3A04%3A22Z&limit=1000&after=1714675441520_1",
                    "userId": "00u99ped55av2JpGs5d7",
                    "warningPercent": "60",
                },
            },
            "displayMessage": "Rate limit warning",
            "eventType": "system.org.rate_limit.warning",
            "legacyEventType": "core.framework.ratelimit.warning",
            "outcome": {"result": "SUCCESS"},
            "published": "2024-05-02 18:46:21.121000000",
            "request": {"ipChain": [{"ip": "11.22.33.44", "version": "V4"}]},
            "securityContext": {},
            "severity": "WARN",
            "target": [
                {"id": "/api/v1/logs", "type": "URL Pattern"},
                {"id": "b192d91c-b242-36da-9332-d97a5579f865", "type": "Bucket Uuid"},
            ],
            "transaction": {
                "detail": {"requestApiTokenId": "00T1bjatrp6Nl1dOc5d7"},
                "id": "234cf34e0081e025e1fe14224464bbd6",
                "type": "WEB",
            },
            "uuid": "44aeb388-08b4-11ef-9cec-73ffcb6f9fdd",
            "version": "0",
        },
    ),
    RuleTest(
        name="Login without marker",
        expected_result=True,
        log={
            "actor": {
                "alternateId": "alice.beaver@company.com",
                "displayName": "Alice Beaver",
                "id": "00u99ped55av2JpGs5d7",
                "type": "User",
            },
            "authenticationContext": {"authenticationStep": 0, "externalSessionId": "trsxcsf59kYRG-GwAbWjw-PZA"},
            "client": {
                "device": "Unknown",
                "ipAddress": "11.22.33.44",
                "userAgent": {"browser": "UNKNOWN", "os": "Unknown", "rawUserAgent": "Go-http-client/2.0"},
                "zone": "null",
            },
            "debugContext": {
                "debugData": {
                    "dtHash": "53dd1a7513e0256eb13b9a47bb07ed61e8ca3d35fbdc36c909567a21a65a2b19",
                    "rateLimitBucketUuid": "b192d91c-b242-36da-9332-d97a5579f865",
                    "rateLimitScopeType": "ORG",
                    "rateLimitSecondsToReset": "6",
                    "requestId": "234cf34e0081e025e1fe14224464bbd6",
                    "requestUri": "/api/v1/logs",
                    "threshold": "20",
                    "timeSpan": "1",
                    "timeUnit": "MINUTES",
                    "url": "/api/v1/logs?since=2023-09-21T17%3A04%3A22Z&limit=1000&after=1714675441520_1",
                    "userId": "00u99ped55av2JpGs5d7",
                    "warningPercent": "60",
                },
            },
            "displayMessage": "Rate limit warning",
            "eventType": "system.org.rate_limit.warning",
            "legacyEventType": "core.framework.ratelimit.warning",
            "outcome": {"result": "SUCCESS"},
            "published": "2024-05-02 18:46:21.121000000",
            "request": {"ipChain": [{"ip": "11.22.33.44", "version": "V4"}]},
            "securityContext": {},
            "severity": "WARN",
            "target": [
                {"id": "/api/v1/logs", "type": "URL Pattern"},
                {"id": "b192d91c-b242-36da-9332-d97a5579f865", "type": "Bucket Uuid"},
            ],
            "transaction": {
                "detail": {"requestApiTokenId": "00T1bjatrp6Nl1dOc5d7"},
                "id": "234cf34e0081e025e1fe14224464bbd6",
                "type": "WEB",
            },
            "uuid": "44aeb388-08b4-11ef-9cec-73ffcb6f9fdd",
            "version": "0",
        },
    ),
]


@panther_managed
class OktaLoginWithoutPushMarker(Rule):
    id = "Okta.Login.Without.Push.Marker-prototype"
    display_name = "Okta Login Without Push Marker"
    enabled = False
    tags = ["Push Security", "Configuration Required"]
    log_types = [LogType.OKTA_SYSTEM_LOG]
    default_severity = Severity.MEDIUM
    tests = okta_login_without_push_marker_tests
    # configure this Push marker based on your environment
    PUSH_MARKER = "PS_mxzqarw"

    def rule(self, event):
        return not event.deep_get("client", "userAgent", "rawUserAgent", default="").endswith(self.PUSH_MARKER)

    def title(self, event):
        actor = event.deep_get("actor", "displayName")
        return f"{actor} logged in from device without expected Push marker"
