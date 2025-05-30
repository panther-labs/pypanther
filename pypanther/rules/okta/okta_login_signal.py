from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class OktaLoginSuccess(Rule):
    id = "Okta.Login.Success-prototype"
    display_name = "Okta Login Signal"
    enabled = False
    create_alert = False
    log_types = [LogType.OKTA_SYSTEM_LOG]
    default_severity = Severity.INFO

    def rule(self, event):
        return event.get("eventType") == "user.session.start" and event.deep_get("outcome", "result") == "SUCCESS"

    def title(self, event):
        return f"{event.deep_get('actor', 'displayName')} logged in to Okta"

    tests = [
        RuleTest(
            name="Non-Login Event",
            expected_result=False,
            log={
                "actor": {
                    "alternateId": "jim.kalafut@panther.com",
                    "displayName": "Jim Kalafut",
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
        RuleTest(
            name="Successful Login",
            expected_result=True,
            log={
                "actor": {
                    "alternateId": "casey.hill@hey.com",
                    "displayName": "Casey Hill",
                    "id": "00ubewfku1EX0WCFk697",
                    "type": "User",
                },
                "authenticationContext": {"authenticationStep": 0, "externalSessionId": "idxvF50v_5sT2-GOA7_K0Amyw"},
                "client": {
                    "device": "Computer",
                    "geographicalContext": {
                        "city": "Atlanta",
                        "country": "United States",
                        "geolocation": {"lat": 33.9794, "lon": -84.3459},
                        "postalCode": "30350",
                        "state": "Georgia",
                    },
                    "ipAddress": "99.108.5.25",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Mac OS 14.4.1 (Sonoma)",
                        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
                    },
                    "zone": "null",
                },
                "debugContext": {
                    "debugData": {
                        "authnRequestId": "5167029d2c8308348d651c0be650230f",
                        "dtHash": "f23be3b6d8bfd69c14e0d1b33e790b84fa5358eab0a09a1058816ad65d633da4",
                        "oktaUserAgentExtended": "okta-auth-js/7.0.1 okta-signin-widget-7.16.1",
                        "origin": "https://trial-2340039.okta.com",
                        "requestId": "601b158a3b3e23be5bbf74d0fe63cd78",
                        "requestUri": "/idp/idx/challenge/answer",
                        "threatSuspected": "false",
                        "url": "/idp/idx/challenge/answer?",
                    },
                },
                "displayMessage": "User login to Okta",
                "eventType": "user.session.start",
                "legacyEventType": "core.user_auth.login_success",
                "outcome": {"result": "SUCCESS"},
                "published": "2024-04-02 19:17:37.621000000",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Atlanta",
                                "country": "United States",
                                "geolocation": {"lat": 33.9794, "lon": -84.3459},
                                "postalCode": "30350",
                                "state": "Georgia",
                            },
                            "ip": "99.108.5.25",
                            "version": "V4",
                        },
                    ],
                },
                "securityContext": {
                    "asNumber": 7018,
                    "asOrg": "at&t corp.",
                    "domain": "sbcglobal.net",
                    "isProxy": False,
                    "isp": "att services inc",
                },
                "severity": "INFO",
                "target": [
                    {
                        "alternateId": "unknown",
                        "displayName": "Password",
                        "id": "lae1at5k3ir9bV1gr697",
                        "type": "AuthenticatorEnrollment",
                    },
                    {
                        "alternateId": "Okta Dashboard",
                        "displayName": "Okta Dashboard",
                        "id": "0oabewfkt83T8ve1o697",
                        "type": "AppInstance",
                    },
                ],
                "transaction": {"detail": {}, "id": "601b158a3b3e23be5bbf74d0fe63cd78", "type": "WEB"},
                "uuid": "aac560bd-f125-11ee-9caa-cd5d09945def",
                "version": "0",
            },
        ),
        RuleTest(
            name="Failed Login",
            expected_result=False,
            log={
                "actor": {
                    "alternateId": "casey.hill@hey.com",
                    "displayName": "Casey Hill",
                    "id": "00ubewfku1EX0WCFk697",
                    "type": "User",
                },
                "authenticationContext": {"authenticationStep": 0, "externalSessionId": "idxvF50v_5sT2-GOA7_K0Amyw"},
                "client": {
                    "device": "Computer",
                    "geographicalContext": {
                        "city": "Atlanta",
                        "country": "United States",
                        "geolocation": {"lat": 33.9794, "lon": -84.3459},
                        "postalCode": "30350",
                        "state": "Georgia",
                    },
                    "ipAddress": "99.108.5.25",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Mac OS 14.4.1 (Sonoma)",
                        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
                    },
                    "zone": "null",
                },
                "debugContext": {
                    "debugData": {
                        "authnRequestId": "5167029d2c8308348d651c0be650230f",
                        "dtHash": "f23be3b6d8bfd69c14e0d1b33e790b84fa5358eab0a09a1058816ad65d633da4",
                        "oktaUserAgentExtended": "okta-auth-js/7.0.1 okta-signin-widget-7.16.1",
                        "origin": "https://trial-2340039.okta.com",
                        "requestId": "601b158a3b3e23be5bbf74d0fe63cd78",
                        "requestUri": "/idp/idx/challenge/answer",
                        "threatSuspected": "false",
                        "url": "/idp/idx/challenge/answer?",
                    },
                },
                "displayMessage": "User login to Okta",
                "eventType": "user.session.start",
                "legacyEventType": "core.user_auth.login_success",
                "outcome": {"result": "FAILURE"},
                "published": "2024-04-02 19:17:37.621000000",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Atlanta",
                                "country": "United States",
                                "geolocation": {"lat": 33.9794, "lon": -84.3459},
                                "postalCode": "30350",
                                "state": "Georgia",
                            },
                            "ip": "99.108.5.25",
                            "version": "V4",
                        },
                    ],
                },
                "securityContext": {
                    "asNumber": 7018,
                    "asOrg": "at&t corp.",
                    "domain": "sbcglobal.net",
                    "isProxy": False,
                    "isp": "att services inc",
                },
                "severity": "INFO",
                "target": [
                    {
                        "alternateId": "unknown",
                        "displayName": "Password",
                        "id": "lae1at5k3ir9bV1gr697",
                        "type": "AuthenticatorEnrollment",
                    },
                    {
                        "alternateId": "Okta Dashboard",
                        "displayName": "Okta Dashboard",
                        "id": "0oabewfkt83T8ve1o697",
                        "type": "AppInstance",
                    },
                ],
                "transaction": {"detail": {}, "id": "601b158a3b3e23be5bbf74d0fe63cd78", "type": "WEB"},
                "uuid": "aac560bd-f125-11ee-9caa-cd5d09945def",
                "version": "0",
            },
        ),
    ]
