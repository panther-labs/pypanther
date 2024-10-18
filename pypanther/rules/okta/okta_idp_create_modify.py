from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.okta import okta_alert_context


@panther_managed
class OktaIdentityProviderCreatedModified(Rule):
    id = "Okta.Identity.Provider.Created.Modified-prototype"
    display_name = "Okta Identity Provider Created or Modified"
    log_types = [LogType.OKTA_SYSTEM_LOG]
    reports = {"MITRE ATT&CK": ["TA0006:T1556", "TA0001:T1199", "TA0003:T1098"]}
    default_severity = Severity.HIGH
    default_description = 'A new 3rd party Identity Provider has been created or modified. Attackers have been observed configuring a second Identity Provider to act as an "impersonation app" to access applications within the compromised Org on behalf of other users. This second Identity Provider, also controlled by the attacker, would act as a “source” IdP in an inbound federation relationship (sometimes called “Org2Org”) with the target.\n'
    default_runbook = "Delegate access to this feature to a Custom Admin Role with the minimum required permissions. Constrain these roles to groups that exclude highly privileged administrators.\n"
    default_reference = "https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection\n"
    dedup_period_minutes = 30

    def rule(self, event):
        return "system.idp.lifecycle" in event.get("eventType")

    def title(self, event):
        action = event.get("eventType").split(".")[-1]
        target = event.deep_walk("target", "displayName", default="<displayName-not-found>", return_val="first")
        return f"{event.deep_get('actor', 'displayName', default='<displayName-not-found>')} <{event.deep_get('actor', 'alternateId', default='alternateId-not-found')}> {action}d Identity Provider [{target}]"

    def severity(self, event):
        if "create" in event.get("eventType"):
            return "HIGH"
        return "MEDIUM"

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
