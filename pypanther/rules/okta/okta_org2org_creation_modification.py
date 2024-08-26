from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get, deep_walk, okta_alert_context

okta_org2org_creation_modification_tests: list[RuleTest] = [
    RuleTest(
        name="Org2Org modified",
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
            "device": {"name": "Evil Computer"},
            "debugcontext": {
                "debugData": {
                    "requestId": "AbCdEf12G",
                    "requestUri": "/api/v1/users/AbCdEfG/lifecycle/reset_factors",
                    "url": "/api/v1/users/AbCdEfG/lifecycle/reset_factors?",
                    "behaviors": {
                        "New Geo-Location=NEGATIVE": None,
                        "New Device=POSITIVE": None,
                        "New IP=POSITIVE": None,
                        "New State=NEGATIVE": None,
                        "New Country=NEGATIVE": None,
                        "Velocity=NEGATIVE": None,
                        "New City=NEGATIVE": None,
                    },
                },
            },
            "displaymessage": "Evaluation of sign-on policy",
            "eventtype": "application.lifecycle.update",
            "outcome": {"reason": "Sign-on policy evaluation resulted in CHALLENGE", "result": "CHALLENGE"},
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
                            "ip": "1.3.2.4",
                            "version": "V4",
                        },
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
                {"alternateId": "Okta Org2Org", "displayName": "Okta Org2Org", "type": "AppInstance"},
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
        name="Org2Org created",
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
            "device": {"name": "Evil Computer"},
            "debugcontext": {
                "debugData": {
                    "requestId": "AbCdEf12G",
                    "requestUri": "/api/v1/users/AbCdEfG/lifecycle/reset_factors",
                    "url": "/api/v1/users/AbCdEfG/lifecycle/reset_factors?",
                    "logOnlySecurityData": {
                        "risk": {"level": "LOW"},
                        "behaviors": {
                            "New Geo-Location": "NEGATIVE",
                            "New Device": "POSITIVE",
                            "New IP": "POSITIVE",
                            "New State": "NEGATIVE",
                            "New Country": "NEGATIVE",
                            "Velocity": "NEGATIVE",
                            "New City": "NEGATIVE",
                        },
                    },
                },
            },
            "displaymessage": "Evaluation of sign-on policy",
            "eventtype": "application.lifecycle.create",
            "outcome": {"reason": "Sign-on policy evaluation resulted in CHALLENGE", "result": "CHALLENGE"},
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
                            "ip": "1.3.2.4",
                            "version": "V4",
                        },
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
                {"alternateId": "Random Org2Org", "displayName": "Random Org2Org", "type": "AppInstance"},
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
        name="Not New Behavior",
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
                    "logOnlySecurityData": {
                        "risk": {"level": "LOW"},
                        "behaviors": {
                            "New Geo-Location": "NEGATIVE",
                            "New Device": "NEGATIVE",
                            "New IP": "NEGATIVE",
                            "New State": "NEGATIVE",
                            "New Country": "NEGATIVE",
                            "Velocity": "NEGATIVE",
                            "New City": "NEGATIVE",
                        },
                    },
                },
            },
            "displaymessage": "Evaluation of sign-on policy",
            "eventtype": "policy.evaluate_sign_on",
            "outcome": {"reason": "Sign-on policy evaluation resulted in CHALLENGE", "result": "CHALLENGE"},
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
                            "ip": "1.3.2.4",
                            "version": "V4",
                        },
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
                {"alternateId": "Okta Admin Console", "displayName": "Okta Admin Console", "type": "AppInstance"},
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
class OktaOrg2orgCreationModification(Rule):
    id = "Okta.Org2org.Creation.Modification-prototype"
    display_name = "Okta Org2Org application created of modified"
    log_types = [LogType.OKTA_SYSTEM_LOG]
    reports = {"MITRE ATT&CK": ["TA0006:T1556", "TA0004:T1078.004"]}
    default_severity = Severity.HIGH
    default_description = "An Okta Org2Org application has been created or modified. Okta's Org2Org applications instances are used to push and match users from one Okta organization to another. A malicious actor can add an Org2Org application instance and create a user in the source organization (controlled by the attacker) with the same identifier as a Super Administrator in the target organization.\n"
    default_reference = (
        "https://www.authomize.com/blog/authomize-discovers-password-stealing-and-impersonation-risks-to-in-okta/\n"
    )
    tests = okta_org2org_creation_modification_tests
    APP_LIFECYCLE_EVENTS = (
        "application.lifecycle.update",
        "application.lifecycle.create",
        "application.lifecycle.activate",
    )

    def rule(self, event):
        if event.get("eventType") not in self.APP_LIFECYCLE_EVENTS:
            return False
        return "Org2Org" in deep_walk(event, "target", "displayName", default="", return_val="first")

    def title(self, event):
        action = event.get("eventType").split(".")[-1]
        target = deep_walk(event, "target", "alternateId", default="<alternateId-not-found>", return_val="first")
        return f"{deep_get(event, 'actor', 'displayName', default='<displayName-not-found>')} <{deep_get(event, 'actor', 'alternateId', default='alternateId-not-found')}> {action}d Org2Org app [{target}]"

    def severity(self, event):
        if "create" in event.get("eventType"):
            return "HIGH"
        return "MEDIUM"

    def alert_context(self, event):
        return okta_alert_context(event)
