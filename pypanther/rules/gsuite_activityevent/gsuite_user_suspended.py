from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GSuiteUserSuspended(Rule):
    id = "GSuite.UserSuspended-prototype"
    display_name = "GSuite User Suspended"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite"]
    default_severity = Severity.HIGH
    default_description = "A GSuite user was suspended, the account may have been compromised by a spam network.\n"
    default_reference = "https://support.google.com/drive/answer/40695?hl=en&sjid=864417124752637253-EU"
    default_runbook = "Investigate the behavior that got the account suspended. Verify with the user that this intended behavior. If not, the account may have been compromised.\n"
    summary_attributes = ["actor:email"]
    USER_SUSPENDED_EVENTS = {
        "account_disabled_generic",
        "account_disabled_spamming_through_relay",
        "account_disabled_spamming",
        "account_disabled_hijacked",
    }

    def rule(self, event):
        if event.deep_get("id", "applicationName") != "login":
            return False
        return bool(event.get("name") in self.USER_SUSPENDED_EVENTS)

    def title(self, event):
        user = event.deep_get("parameters", "affected_email_address")
        if not user:
            user = "<UNKNOWN_USER>"
        return f"User [{user}]'s account was disabled"

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
            name="Account Warning Not For User Suspended",
            expected_result=False,
            log={
                "id": {"applicationName": "login"},
                "kind": "admin#reports#activity",
                "type": "account_warning",
                "name": "suspicious_login ",
                "parameters": {"affected_email_address": "bobert@ext.runpanther.io"},
            },
        ),
        RuleTest(
            name="Account Warning For Suspended User",
            expected_result=True,
            log={
                "id": {"applicationName": "login"},
                "kind": "admin#reports#activity",
                "type": "account_warning",
                "name": "account_disabled_spamming",
                "parameters": {"affected_email_address": "bobert@ext.runpanther.io"},
            },
        ),
    ]
