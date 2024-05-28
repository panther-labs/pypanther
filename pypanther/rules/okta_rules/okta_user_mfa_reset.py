from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import okta_alert_context
from pypanther.log_types import LogType

okta_user_mfa_reset_single_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="User reset own MFA factor",
        ExpectedResult=True,
        Log={
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
                }
            ],
            "authenticationcontext": {"authenticationStep": 0, "externalSessionId": "1111111"},
            "p_log_type": "Okta.SystemLog",
        },
    ),
    PantherRuleTest(
        Name="Other Event",
        ExpectedResult=False,
        Log={
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
            "target": [
                {"alternateId": "App ", "displayName": "App", "id": "12345", "type": "AppInstance"}
            ],
            "transaction": {"detail": {}, "id": "sdfg", "type": "JOB"},
            "uuid": "aaa-bb-ccc",
            "version": "0",
        },
    ),
]


class OktaUserMFAResetSingle(PantherRule):
    Description = "User has reset one of their own MFA factors"
    DisplayName = "Okta User MFA Own Reset"
    RuleID = "Okta.User.MFA.Reset.Single-prototype"
    Reference = "https://support.okta.com/help/s/article/How-to-avoid-lockouts-and-reset-your-Multifactor-Authentication-MFA-for-Okta-Admins?language=en_US"
    Severity = PantherSeverity.Info
    LogTypes = [LogType.Okta_SystemLog]
    Tests = okta_user_mfa_reset_single_tests

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
