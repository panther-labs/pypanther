from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.okta import okta_alert_context


@panther_managed
class OktaUserAccountLocked(Rule):
    default_description = "An Okta user has locked their account."
    display_name = "Okta User Account Locked"
    default_reference = "https://support.okta.com/help/s/article/How-to-Configure-the-Number-of-Failed-Login-Attempts-Before-User-Lockout?language=en_US"
    default_severity = Severity.LOW
    log_types = [LogType.OKTA_SYSTEM_LOG]
    id = "Okta.User.Account.Locked-prototype"

    def rule(self, event):
        return event.get("eventtype") in ("user.account.lock", "user.account.lock.limit")

    def title(self, event):
        return f"Okta: [{event.get('actor', {}).get('alternateId', '<id-not-found>')}] [{event.get('displaymessage', 'account has been locked.')}]"

    def alert_context(self, event):
        return okta_alert_context(event)

    tests = [
        RuleTest(
            name="Account Lock Event",
            expected_result=True,
            log={
                "actor": {
                    "alternateId": "homer.simpson@duff.com",
                    "displayName": "Homer Simpson",
                    "id": "00abc123",
                    "type": "User",
                },
                "authenticationcontext": {"authenticationStep": 0, "externalSessionId": "abcd-1234"},
                "client": {
                    "device": "Computer",
                    "geographicalContext": {
                        "city": "Atlanta",
                        "country": "United States",
                        "geolocation": {"lat": 33, "lon": -80},
                        "postalCode": "30318",
                        "state": "Georgia",
                    },
                    "ipAddress": "1.2.3.4",
                    "userAgent": {"browser": "CHROME", "os": "Mac OS X", "rawUserAgent": "Chrome"},
                    "zone": "null",
                },
                "debugcontext": {
                    "debugData": {
                        "deviceFingerprint": "abc1234",
                        "dtHash": "000abc",
                        "requestId": "abc1111",
                        "requestUri": "/idp/idx/identify",
                        "threatSuspected": "false",
                        "url": "/idp/idx/identify?",
                    },
                },
                "displaymessage": "Account Locked from New Devices - Max sign-in attempts exceeded.",
                "eventtype": "user.account.lock",
                "legacyeventtype": "core.user_auth.account_locked",
                "outcome": {"reason": "LOCKED_OUT", "result": "FAILURE"},
                "published": "2022-11-22 18:48:49.177",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Atlanta",
                                "country": "United States",
                                "geolocation": {"lat": 33, "lon": -80},
                                "postalCode": "30318",
                                "state": "Georgia",
                            },
                            "ip": "1.2.3.4",
                            "version": "V4",
                        },
                    ],
                },
                "securitycontext": {
                    "asNumber": 7018,
                    "asOrg": "at&t corp.",
                    "domain": "sbcglobal.net",
                    "isProxy": False,
                    "isp": "att services inc",
                },
                "severity": "DEBUG",
                "transaction": {"detail": {}, "id": "12345aaa", "type": "WEB"},
                "uuid": "aa-bb-cc-11",
                "version": "0",
            },
        ),
        RuleTest(
            name="Non Event",
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
                "target": [
                    {"alternateId": "App (123)", "displayName": "App (123)", "id": "12345", "type": "AppInstance"},
                ],
                "transaction": {"detail": {}, "id": "aaa-bbb-123", "type": "WEB"},
                "uuid": "aa-11-22-33-44-bb",
                "version": "0",
            },
        ),
    ]
