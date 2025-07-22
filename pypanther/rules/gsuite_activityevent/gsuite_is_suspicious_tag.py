from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GSuiteIsSuspiciousTag(Rule):
    id = "GSuite.IsSuspiciousTag-prototype"
    display_name = "Suspicious is_suspicious tag"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite", "Beta"]
    default_severity = Severity.INFO
    default_description = "GSuite reported a suspicious activity for this user.\n"
    default_reference = "https://support.google.com/a/answer/7102416?hl=en"
    default_runbook = "Checkout the details of the activity and verify this behavior with the user to ensure the account wasn't compromised.\n"
    summary_attributes = ["actor:email"]

    def rule(self, event):
        return event.deep_get("parameters", "is_suspicious") is True

    def title(self, event):
        user = event.deep_get("actor", "email", default="<UNKNOWN_USER>")
        return f"A suspicious action was reported for user [{user}]"

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
