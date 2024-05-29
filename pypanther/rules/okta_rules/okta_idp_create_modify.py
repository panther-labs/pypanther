from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get, deep_walk, okta_alert_context
from pypanther.log_types import LogType

okta_identity_provider_created_modified_tests: List[PantherRuleTest] = [
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
            "eventtype": "system.idp.lifecycle.create",
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
]


class OktaIdentityProviderCreatedModified(PantherRule):
    RuleID = "Okta.Identity.Provider.Created.Modified-prototype"
    DisplayName = "Okta Identity Provider Created or Modified"
    LogTypes = [LogType.Okta_SystemLog]
    Reports = {"MITRE ATT&CK": ["TA0006:T1556", "TA0001:T1199", "TA0003:T1098"]}
    Severity = PantherSeverity.High
    Description = 'A new 3rd party Identity Provider has been created or modified. Attackers have been observed configuring a second Identity Provider to act as an "impersonation app" to access applications within the compromised Org on behalf of other users. This second Identity Provider, also controlled by the attacker, would act as a “source” IdP in an inbound federation relationship (sometimes called “Org2Org”) with the target.\n'
    Runbook = "Delegate access to this feature to a Custom Admin Role with the minimum required permissions. Constrain these roles to groups that exclude highly privileged administrators.\n"
    Reference = "https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection\n"
    DedupPeriodMinutes = 30
    Tests = okta_identity_provider_created_modified_tests

    def rule(self, event):
        return "system.idp.lifecycle" in event.get("eventType")

    def title(self, event):
        action = event.get("eventType").split(".")[3]
        target = deep_walk(
            event, "target", "displayName", default="<displayName-not-found>", return_val="first"
        )
        return f"{deep_get(event, 'actor', 'displayName', default='<displayName-not-found>')} <{deep_get(event, 'actor', 'alternateId', default='alternateId-not-found')}> {action}d Identity Provider [{target}]"

    def severity(self, event):
        if "create" in event.get("eventType"):
            return "HIGH"
        return "MEDIUM"

    def alert_context(self, event):
        return okta_alert_context(event)
