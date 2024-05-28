from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

g_suite_leaked_password_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Normal Login Event",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "login"},
            "type": "login",
            "name": "logout",
            "parameters": {"login_type": "saml"},
        },
    ),
    PantherRuleTest(
        Name="Account Warning Not For Password Leaked",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "login"},
            "type": "account_warning",
            "name": "account_disabled_spamming",
            "parameters": {"affected_email_address": "homer.simpson@example.com"},
        },
    ),
    PantherRuleTest(
        Name="Account Warning For Password Leaked",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "login"},
            "type": "account_warning",
            "name": "account_disabled_password_leak",
            "parameters": {"affected_email_address": "homer.simpson@example.com"},
        },
    ),
]


class GSuiteLeakedPassword(PantherRule):
    RuleID = "GSuite.LeakedPassword-prototype"
    DisplayName = "GSuite User Password Leaked"
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite", "Credential Access:Unsecured Credentials"]
    Reports = {"MITRE ATT&CK": ["TA0006:T1552"]}
    Severity = PantherSeverity.High
    Description = (
        "GSuite reported a user's password has been compromised, so they disabled the account.\n"
    )
    Reference = "https://support.google.com/a/answer/2984349?hl=en#zippy=%2Cstep-temporarily-suspend-the-suspected-compromised-user-account%2Cstep-investigate-the-account-for-unauthorized-activity%2Cstep-revoke-access-to-the-affected-account%2Cstep-return-access-to-the-user-again%2Cstep-enroll-in--step-verification-with-security-keys%2Cstep-add-secure-or-update-recovery-options%2Cstep-enable-account-activity-alerts"
    Runbook = "GSuite has already disabled the compromised user's account. Consider investigating how the user's account was compromised, and reset their account and password. Advise the user to change any other passwords in use that are the sae as the compromised password.\n"
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_leaked_password_tests
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
