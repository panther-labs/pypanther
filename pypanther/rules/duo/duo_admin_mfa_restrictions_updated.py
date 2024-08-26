from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_duo_helpers import duo_alert_context

duo_admin_mfa_restrictions_updated_tests: list[RuleTest] = [
    RuleTest(
        name="Admin MFA Update Event",
        expected_result=True,
        log={
            "action": "update_admin_factor_restrictions",
            "description": '{"allowed_factors": "Duo mobile passcodes, Hardware tokens, Duo push, Yubikey aes"}',
            "isotimestamp": "2022-02-21 21:48:06",
            "timestamp": "2022-02-21 21:48:06",
            "username": "Homer Simpson",
        },
    ),
    RuleTest(
        name="Login Event",
        expected_result=False,
        log={
            "action": "admin_login",
            "description": '{"ip_address": "1.2.3.4", "device": "123-456-789", "factor": "sms", "saml_idp": "OneLogin", "primary_auth_method": "Single Sign-On"}',
            "isotimestamp": "2021-06-30 19:45:37",
            "timestamp": "2021-06-30 19:45:37",
            "username": "Homer Simpson",
        },
    ),
]


@panther_managed
class DuoAdminMFARestrictionsUpdated(Rule):
    default_description = "Detects changes to allowed MFA factors administrators can use to log into the admin panel."
    display_name = "Duo Admin MFA Restrictions Updated"
    default_reference = "https://duo.com/docs/essentials-overview"
    default_severity = Severity.MEDIUM
    log_types = [LogType.DUO_ADMINISTRATOR]
    id = "Duo.Admin.MFA.Restrictions.Updated-prototype"
    tests = duo_admin_mfa_restrictions_updated_tests

    def rule(self, event):
        return event.get("action") == "update_admin_factor_restrictions"

    def title(self, event):
        return f"Duo Admin MFA Restrictions Updated by [{event.get('username', '<user_not_found>')}]"

    def alert_context(self, event):
        return duo_alert_context(event)
