from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


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
    SUSPICIOUS_LOGIN_TYPES = {"suspicious_login", "suspicious_login_less_secure_app", "suspicious_programmatic_login"}

    def rule(self, event):
        if event.deep_get("id", "applicationName") != "login":
            return False
        if event.get("name") in self.SUSPICIOUS_LOGIN_TYPES:
            return True
        if event.deep_get("parameters", "is_suspicious") is True:
            return True
        return False

    def title(self, event):
        user = event.deep_get("actor", "email")
        if not user:
            user = "<UNKNOWN_USER>"
        return f"A suspicious login was reported for user [{user}]"

    tests = [
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
        RuleTest(
            name="Login Success But Flagged Suspicious",
            expected_result=True,
            log={
                "id": {"applicationName": "login"},
                "actor": {"email": 'bobert@ext.runpanther.io"'},
                "kind": "admin#reports#activity",
                "type": "login",
                "name": "login_success",
                "parameters": {"affected_email_address": "bobert@ext.runpanther.io", "is_suspicious": True},
            },
        ),
    ]
