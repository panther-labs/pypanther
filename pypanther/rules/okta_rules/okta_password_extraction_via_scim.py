from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get, deep_walk, okta_alert_context
from pypanther.log_types import LogType

okta_password_extractionvia_scim_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Other Event",
        ExpectedResult=False,
        Log={
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
                }
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
                    }
                ]
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
                }
            ],
            "transaction": {"detail": {}, "id": "ABcDeFgG", "type": "WEB"},
            "uuid": "AbC-123-XyZ",
            "version": "0",
        },
    ),
    PantherRuleTest(
        Name="FastPass Phishing Block Event",
        ExpectedResult=True,
        Log={
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
                }
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
                    }
                ]
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
                }
            ],
            "transaction": {"detail": {}, "id": "ABcDeFgG", "type": "WEB"},
            "uuid": "AbC-123-XyZ",
            "version": "0",
        },
    ),
]


class OktaPasswordExtractionviaSCIM(PantherRule):
    RuleID = "Okta.Password.Extraction.via.SCIM-prototype"
    DisplayName = "Okta Cleartext Passwords Extracted via SCIM Application"
    LogTypes = [LogType.Okta_SystemLog]
    Reports = {"MITRE ATT&CK": ["TA0006:T1556"]}
    Severity = PantherSeverity.High
    Description = "An application admin has extracted cleartext user passwords via SCIM app. Malcious actors can extract plaintext passwords by creating a SCIM application under their control and configuring it to sync passwords from Okta.\n"
    Reference = "https://www.authomize.com/blog/authomize-discovers-password-stealing-and-impersonation-risks-to-in-okta/\n"
    DedupPeriodMinutes = 30
    Tests = okta_password_extractionvia_scim_tests

    def rule(self, event):
        return event.get(
            "eventType"
        ) == "application.lifecycle.update" and "Pushing user passwords" in deep_get(
            event, "outcome", "reason", default=""
        )

    def title(self, event):
        target = deep_walk(
            event, "target", "alternateId", default="<alternateId-not-found>", return_val="first"
        )
        return f"{deep_get(event, 'actor', 'displayName', default='<displayName-not-found>')} <{deep_get(event, 'actor', 'alternateId', default='alternateId-not-found')}> extracted cleartext user passwords via SCIM app [{target}]"

    def alert_context(self, event):
        return okta_alert_context(event)
