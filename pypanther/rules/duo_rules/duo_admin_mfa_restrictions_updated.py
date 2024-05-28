from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_duo_helpers import duo_alert_context
from pypanther.log_types import LogType

duo_admin_mfa_restrictions_updated_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Admin MFA Update Event",
        ExpectedResult=True,
        Log={
            "action": "update_admin_factor_restrictions",
            "description": '{"allowed_factors": "Duo mobile passcodes, Hardware tokens, Duo push, Yubikey aes"}',
            "isotimestamp": "2022-02-21 21:48:06",
            "timestamp": "2022-02-21 21:48:06",
            "username": "Homer Simpson",
        },
    ),
    PantherRuleTest(
        Name="Login Event",
        ExpectedResult=False,
        Log={
            "action": "admin_login",
            "description": '{"ip_address": "1.2.3.4", "device": "123-456-789", "factor": "sms", "saml_idp": "OneLogin", "primary_auth_method": "Single Sign-On"}',
            "isotimestamp": "2021-06-30 19:45:37",
            "timestamp": "2021-06-30 19:45:37",
            "username": "Homer Simpson",
        },
    ),
]


class DuoAdminMFARestrictionsUpdated(PantherRule):
    Description = (
        "Detects changes to allowed MFA factors administrators can use to log into the admin panel."
    )
    DisplayName = "Duo Admin MFA Restrictions Updated"
    Reference = "https://duo.com/docs/essentials-overview"
    Severity = PantherSeverity.Medium
    LogTypes = [LogType.Duo_Administrator]
    RuleID = "Duo.Admin.MFA.Restrictions.Updated-prototype"
    Tests = duo_admin_mfa_restrictions_updated_tests

    def rule(self, event):
        return event.get("action") == "update_admin_factor_restrictions"

    def title(self, event):
        return (
            f"Duo Admin MFA Restrictions Updated by [{event.get('username', '<user_not_found>')}]"
        )

    def alert_context(self, event):
        return duo_alert_context(event)
