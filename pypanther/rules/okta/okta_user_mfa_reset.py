from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers import event_type
from pypanther.helpers.okta import okta_alert_context


@panther_managed
class OktaUserMFAResetSingle(Rule):
    default_description = "User has reset one of their own MFA factors"
    display_name = "Okta User MFA Own Reset"
    id = "Okta.User.MFA.Reset.Single-prototype"
    default_reference = "https://support.okta.com/help/s/article/How-to-avoid-lockouts-and-reset-your-Multifactor-Authentication-MFA-for-Okta-Admins?language=en_US"
    default_severity = Severity.INFO
    log_types = [LogType.OKTA_SYSTEM_LOG]

    def rule(self, event):
        return event.udm("event_type") == event_type.MFA_RESET

    def title(self, event):
        try:
            which_factor = event.get("outcome", {}).get("reason", "").split()[2]
        except IndexError:
            which_factor = "<FACTOR_NOT_FOUND>"
        return f"Okta: User reset their MFA factor [{which_factor}] [{event.get('target', [{}])[0].get('alternateId', '<id-not-found>')}] by [{event.get('actor', {}).get('alternateId', '<id-not-found>')}]"

    def alert_context(self, event):
        return okta_alert_context(event)

    tests = [
        RuleTest(
            name="User reset own MFA factor",
            expected_result=True,
            log={
                "eventtype": "user.mfa.factor.deactivate",
                "version": "0",
                "severity": "INFO",
                "displaymessage": "Reset factor for user",
                "actor": {
                    "alternateId": "homer@springfield.gov",
                    "displayName": "Homer Simpson",
                    "id": "11111111111",
                    "type": "User",
                },
                "client": {
                    "device": "Computer",
                    "ipAddress": "1.1.1.1",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Mac OS X",
                        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36",
                    },
                    "zone": "null",
                },
                "outcome": {"reason": "User reset FIDO_WEBAUTHN factor", "result": "SUCCESS"},
                "target": [
                    {
                        "alternateId": "homer@springfield.gov",
                        "displayName": "Homer Simpson",
                        "id": "1111111",
                        "type": "User",
                    },
                ],
                "authenticationcontext": {"authenticationStep": 0, "externalSessionId": "1111111"},
                "p_log_type": "Okta.SystemLog",
            },
        ),
        RuleTest(
            name="Other Event",
            expected_result=False,
            log={
                "p_log_type": "Okta.SystemLog",
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
