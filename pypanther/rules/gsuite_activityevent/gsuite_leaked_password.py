from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

g_suite_leaked_password_tests: list[RuleTest] = [
    RuleTest(
        name="Normal Login Event",
        expected_result=False,
        log={
            "id": {"applicationName": "login"},
            "type": "login",
            "name": "logout",
            "parameters": {"login_type": "saml"},
        },
    ),
    RuleTest(
        name="Account Warning Not For Password Leaked",
        expected_result=False,
        log={
            "id": {"applicationName": "login"},
            "type": "account_warning",
            "name": "account_disabled_spamming",
            "parameters": {"affected_email_address": "homer.simpson@example.com"},
        },
    ),
    RuleTest(
        name="Account Warning For Password Leaked",
        expected_result=True,
        log={
            "id": {"applicationName": "login"},
            "type": "account_warning",
            "name": "account_disabled_password_leak",
            "parameters": {"affected_email_address": "homer.simpson@example.com"},
        },
    ),
]


@panther_managed
class GSuiteLeakedPassword(Rule):
    id = "GSuite.LeakedPassword-prototype"
    display_name = "GSuite User Password Leaked"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite", "Credential Access:Unsecured Credentials"]
    reports = {"MITRE ATT&CK": ["TA0006:T1552"]}
    default_severity = Severity.HIGH
    default_description = "GSuite reported a user's password has been compromised, so they disabled the account.\n"
    default_reference = "https://support.google.com/a/answer/2984349?hl=en#zippy=%2Cstep-temporarily-suspend-the-suspected-compromised-user-account%2Cstep-investigate-the-account-for-unauthorized-activity%2Cstep-revoke-access-to-the-affected-account%2Cstep-return-access-to-the-user-again%2Cstep-enroll-in--step-verification-with-security-keys%2Cstep-add-secure-or-update-recovery-options%2Cstep-enable-account-activity-alerts"
    default_runbook = "GSuite has already disabled the compromised user's account. Consider investigating how the user's account was compromised, and reset their account and password. Advise the user to change any other passwords in use that are the sae as the compromised password.\n"
    summary_attributes = ["actor:email"]
    tests = g_suite_leaked_password_tests
    PASSWORD_LEAKED_EVENTS = {"account_disabled_password_leak"}

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "login":
            return False
        if event.get("type") == "account_warning":
            return bool(event.get("name") in self.PASSWORD_LEAKED_EVENTS)
        return False

    def title(self, event):
        user = deep_get(event, "parameters", "affected_email_address")
        if not user:
            user = "<UNKNOWN_USER>"
        return f"User [{user}]'s account was disabled due to a password leak"
