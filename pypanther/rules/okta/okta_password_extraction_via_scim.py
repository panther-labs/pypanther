from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.okta import okta_alert_context


@panther_managed
class OktaPasswordExtractionviaSCIM(Rule):
    id = "Okta.Password.Extraction.via.SCIM-prototype"
    display_name = "Okta Cleartext Passwords Extracted via SCIM Application"
    log_types = [LogType.OKTA_SYSTEM_LOG]
    reports = {"MITRE ATT&CK": ["TA0006:T1556"]}
    default_severity = Severity.HIGH
    default_description = "An application admin has extracted cleartext user passwords via SCIM app. Malcious actors can extract plaintext passwords by creating a SCIM application under their control and configuring it to sync passwords from Okta.\n"
    default_reference = (
        "https://www.authomize.com/blog/authomize-discovers-password-stealing-and-impersonation-risks-to-in-okta/\n"
    )
    dedup_period_minutes = 30

    def rule(self, event):
        return event.get("eventType") == "application.lifecycle.update" and "Pushing user passwords" in event.deep_get(
            "outcome",
            "reason",
            default="",
        )

    def title(self, event):
        target = event.deep_walk("target", "alternateId", default="<alternateId-not-found>", return_val="first")
        return f"{event.deep_get('actor', 'displayName', default='<displayName-not-found>')} <{event.deep_get('actor', 'alternateId', default='alternateId-not-found')}> extracted cleartext user passwords via SCIM app [{target}]"

    def alert_context(self, event):
        return okta_alert_context(event)

    tests = [
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
                "eventtype": "application.lifecycle.update",
                "legacyeventtype": "core.user.factor.attempt_fail",
                "outcome": {"reason": "Pushing user passwords", "result": "SUCCESS"},
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
