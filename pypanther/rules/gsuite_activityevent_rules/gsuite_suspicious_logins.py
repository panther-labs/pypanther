from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

g_suite_suspicious_logins_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Normal Login Event",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "login"},
            "kind": "admin#reports#activity",
            "type": "account_warning",
            "name": "login_success",
            "parameters": {"affected_email_address": "bobert@ext.runpanther.io"},
        },
    ),
    PantherRuleTest(
        Name="Account Warning Not For Suspicious Login",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "login"},
            "kind": "admin#reports#activity",
            "type": "account_warning",
            "name": "account_disabled_spamming",
            "parameters": {"affected_email_address": "bobert@ext.runpanther.io"},
        },
    ),
    PantherRuleTest(
        Name="Account Warning For Suspicious Login",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "login"},
            "kind": "admin#reports#activity",
            "type": "account_warning",
            "name": "suspicious_login",
            "parameters": {"affected_email_address": "bobert@ext.runpanther.io"},
        },
    ),
]


class GSuiteSuspiciousLogins(PantherRule):
    RuleID = "GSuite.SuspiciousLogins-prototype"
    DisplayName = "Suspicious GSuite Login"
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite"]
    Severity = PantherSeverity.Medium
    Description = "GSuite reported a suspicious login for this user.\n"
    Reference = "https://support.google.com/a/answer/7102416?hl=en"
    Runbook = "Checkout the details of the login and verify this behavior with the user to ensure the account wasn't compromised.\n"
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_suspicious_logins_tests
    SUSPICIOUS_LOGIN_TYPES = {
        "suspicious_login",
        "suspicious_login_less_secure_app",
        "suspicious_programmatic_login",
    }

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "login":
            return False
        return bool(event.get("name") in self.SUSPICIOUS_LOGIN_TYPES)

    def title(self, event):
        user = deep_get(event, "parameters", "affected_email_address")
        if not user:
            user = "<UNKNOWN_USER>"
        return f"A suspicious login was reported for user [{user}]"
