from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

g_suite_suspicious_logins_tests: list[RuleTest] = [
    RuleTest(
        name="Normal Login Event",
        expected_result=False,
        log={
            "id": {"applicationName": "login"},
            "kind": "admin#reports#activity",
            "type": "account_warning",
            "name": "login_success",
            "parameters": {"affected_email_address": "bobert@ext.runpanther.io"},
        },
    ),
    RuleTest(
        name="Account Warning Not For Suspicious Login",
        expected_result=False,
        log={
            "id": {"applicationName": "login"},
            "kind": "admin#reports#activity",
            "type": "account_warning",
            "name": "account_disabled_spamming",
            "parameters": {"affected_email_address": "bobert@ext.runpanther.io"},
        },
    ),
    RuleTest(
        name="Account Warning For Suspicious Login",
        expected_result=True,
        log={
            "id": {"applicationName": "login"},
            "kind": "admin#reports#activity",
            "type": "account_warning",
            "name": "suspicious_login",
            "parameters": {"affected_email_address": "bobert@ext.runpanther.io"},
        },
    ),
]


@panther_managed
class GSuiteSuspiciousLogins(Rule):
    id = "GSuite.SuspiciousLogins-prototype"
    display_name = "Suspicious GSuite Login"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite"]
    default_severity = Severity.MEDIUM
    default_description = "GSuite reported a suspicious login for this user.\n"
    default_reference = "https://support.google.com/a/answer/7102416?hl=en"
    default_runbook = "Checkout the details of the login and verify this behavior with the user to ensure the account wasn't compromised.\n"
    summary_attributes = ["actor:email"]
    tests = g_suite_suspicious_logins_tests
    SUSPICIOUS_LOGIN_TYPES = {"suspicious_login", "suspicious_login_less_secure_app", "suspicious_programmatic_login"}

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "login":
            return False
        return bool(event.get("name") in self.SUSPICIOUS_LOGIN_TYPES)

    def title(self, event):
        user = deep_get(event, "parameters", "affected_email_address")
        if not user:
            user = "<UNKNOWN_USER>"
        return f"A suspicious login was reported for user [{user}]"
