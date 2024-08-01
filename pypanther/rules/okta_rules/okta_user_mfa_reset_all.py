from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import okta_alert_context

okta_user_mfa_reset_all_tests: list[RuleTest] = [
    RuleTest(
        name="Reset All Event",
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
            "displaymessage": "Reset all factors for user",
            "eventtype": "user.mfa.factor.reset_all",
            "legacyeventtype": "core.user.factor.reset_all",
            "outcome": {"result": "SUCCESS"},
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
        name="Other Event",
        expected_result=False,
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
]


@panther_managed
class OktaUserMFAResetAll(Rule):
    default_description = "All MFA factors have been reset for a user."
    display_name = "Okta User MFA Reset All"
    default_reference = "https://help.okta.com/en-us/content/topics/security/mfa/mfa-reset-users.htm#:~:text=the%20Admin%20Console%3A-,In%20the%20Admin%20Console%2C%20go%20to%20DirectoryPeople.,Selected%20Factors%20or%20Reset%20All"
    default_severity = Severity.LOW
    log_types = [LogType.OKTA_SYSTEM_LOG]
    id = "Okta.User.MFA.Reset.All-prototype"
    tests = okta_user_mfa_reset_all_tests

    def rule(self, event):
        return event.get("eventtype") == "user.mfa.factor.reset_all"

    def title(self, event):
        return f"Okta: All MFA factors were reset for [{event.get('target', [{}])[0].get('alternateId', '<id-not-found>')}] by [{event.get('actor', {}).get('alternateId', '<id-not-found>')}]"

    def alert_context(self, event):
        return okta_alert_context(event)
