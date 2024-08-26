from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get, okta_alert_context

okta_phishing_attempt_blocked_fast_pass_tests: list[RuleTest] = [
    RuleTest(
        name="Other Event",
        expected_result=False,
        log={
            "actor": {
                "alternateId": "homer.simpson@duff.com",
                "displayName": "Homer Simpson",
                "id": "00abc123",
                "type": "User",
            },
            "authenticationcontext": {"authenticationStep": 0, "externalSessionId": "100-abc-9999"},
            "client": {
                "device": "Computer",
                "geographicalContext": {
                    "city": "Springfield",
                    "country": "United States",
                    "geolocation": {"lat": 20, "lon": -25},
                    "postalCode": "12345",
                    "state": "Ohio",
                },
                "ipAddress": "1.3.2.4",
                "userAgent": {
                    "browser": "CHROME",
                    "os": "Mac OS X",
                    "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
                },
                "zone": "null",
            },
            "debugcontext": {
                "debugData": {
                    "requestId": "AbCdEf12G",
                    "requestUri": "/api/v1/users/AbCdEfG/lifecycle/reset_factors",
                    "url": "/api/v1/users/AbCdEfG/lifecycle/reset_factors?",
                },
            },
            "displaymessage": "Authentication of user via MFA",
            "eventtype": "user.authentication.auth_via_mfa",
            "legacyeventtype": "core.user.factor.attempt_fail",
            "outcome": {"reason": "INVALID_CREDENTIALS", "result": "FAILURE"},
            "published": "2022-06-22 18:18:29.015",
            "request": {
                "ipChain": [
                    {
                        "geographicalContext": {
                            "city": "Springfield",
                            "country": "United States",
                            "geolocation": {"lat": 20, "lon": -25},
                            "postalCode": "12345",
                            "state": "Ohio",
                        },
                        "ip": "1.3.2.4",
                        "version": "V4",
                    },
                ],
            },
            "securitycontext": {
                "asNumber": 701,
                "asOrg": "verizon",
                "domain": "verizon.net",
                "isProxy": False,
                "isp": "verizon",
            },
            "severity": "INFO",
            "target": [
                {
                    "alternateId": "peter.griffin@company.com",
                    "displayName": "Peter Griffin",
                    "id": "0002222AAAA",
                    "type": "User",
                },
            ],
            "transaction": {"detail": {}, "id": "ABcDeFgG", "type": "WEB"},
            "uuid": "AbC-123-XyZ",
            "version": "0",
        },
    ),
    RuleTest(
        name="FastPass Phishing Block Event",
        expected_result=True,
        log={
            "actor": {
                "alternateId": "homer.simpson@duff.com",
                "displayName": "Homer Simpson",
                "id": "00abc123",
                "type": "User",
            },
            "authenticationcontext": {"authenticationStep": 0, "externalSessionId": "100-abc-9999"},
            "client": {
                "device": "Computer",
                "geographicalContext": {
                    "city": "Springfield",
                    "country": "United States",
                    "geolocation": {"lat": 20, "lon": -25},
                    "postalCode": "12345",
                    "state": "Ohio",
                },
                "ipAddress": "1.3.2.4",
                "userAgent": {
                    "browser": "CHROME",
                    "os": "Mac OS X",
                    "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
                },
                "zone": "null",
            },
            "debugcontext": {
                "debugData": {
                    "requestId": "AbCdEf12G",
                    "requestUri": "/api/v1/users/AbCdEfG/lifecycle/reset_factors",
                    "url": "/api/v1/users/AbCdEfG/lifecycle/reset_factors?",
                },
            },
            "displaymessage": "Authentication of user via MFA",
            "eventtype": "user.authentication.auth_via_mfa",
            "legacyeventtype": "core.user.factor.attempt_fail",
            "outcome": {"reason": "FastPass declined phishing attempt", "result": "FAILURE"},
            "published": "2022-06-22 18:18:29.015",
            "request": {
                "ipChain": [
                    {
                        "geographicalContext": {
                            "city": "Springfield",
                            "country": "United States",
                            "geolocation": {"lat": 20, "lon": -25},
                            "postalCode": "12345",
                            "state": "Ohio",
                        },
                        "ip": "1.3.2.4",
                        "version": "V4",
                    },
                ],
            },
            "securitycontext": {
                "asNumber": 701,
                "asOrg": "verizon",
                "domain": "verizon.net",
                "isProxy": False,
                "isp": "verizon",
            },
            "severity": "INFO",
            "target": [
                {
                    "alternateId": "peter.griffin@company.com",
                    "displayName": "Peter Griffin",
                    "id": "0002222AAAA",
                    "type": "User",
                },
            ],
            "transaction": {"detail": {}, "id": "ABcDeFgG", "type": "WEB"},
            "uuid": "AbC-123-XyZ",
            "version": "0",
        },
    ),
]


@panther_managed
class OktaPhishingAttemptBlockedFastPass(Rule):
    id = "Okta.Phishing.Attempt.Blocked.FastPass-prototype"
    display_name = "Okta AiTM Phishing Attempt Blocked by FastPass"
    log_types = [LogType.OKTA_SYSTEM_LOG]
    reports = {"MITRE ATT&CK": ["TA0001:T1566", "TA0006:T1556", "TA0003:T1078.004"]}
    default_severity = Severity.HIGH
    default_description = "Okta FastPass detected a user targeted by attackers wielding real-time (AiTM) proxies.\n"
    default_runbook = (
        "Protect sign-in flows by enforcing phishing-resistant authentication with Okta FastPass and FIDO2 WebAuthn.\n"
    )
    default_reference = "https://sec.okta.com/fastpassphishingdetection\n"
    dedup_period_minutes = 30
    tests = okta_phishing_attempt_blocked_fast_pass_tests

    def rule(self, event):
        return (
            event.get("eventType") == "user.authentication.auth_via_mfa"
            and deep_get(event, "outcome", "result") == "FAILURE"
            and (deep_get(event, "outcome", "reason") == "FastPass declined phishing attempt")
        )

    def title(self, event):
        return f"{deep_get(event, 'actor', 'displayName', default='<displayName-not-found>')} <{deep_get(event, 'actor', 'alternateId', default='alternateId-not-found')}> FastPass declined phishing attempt"

    def alert_context(self, event):
        return okta_alert_context(event)
