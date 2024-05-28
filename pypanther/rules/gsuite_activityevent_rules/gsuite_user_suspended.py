from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

g_suite_user_suspended_tests: List[PantherRuleTest] = [
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
        Name="Account Warning Not For User Suspended",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "login"},
            "kind": "admin#reports#activity",
            "type": "account_warning",
            "name": "suspicious_login ",
            "parameters": {"affected_email_address": "bobert@ext.runpanther.io"},
        },
    ),
    PantherRuleTest(
        Name="Account Warning For Suspended User",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "login"},
            "kind": "admin#reports#activity",
            "type": "account_warning",
            "name": "account_disabled_spamming",
            "parameters": {"affected_email_address": "bobert@ext.runpanther.io"},
        },
    ),
]


class GSuiteUserSuspended(PantherRule):
    RuleID = "GSuite.UserSuspended-prototype"
    DisplayName = "GSuite User Suspended"
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite"]
    Severity = PantherSeverity.High
    Description = (
        "A GSuite user was suspended, the account may have been compromised by a spam network.\n"
    )
    Reference = "https://support.google.com/drive/answer/40695?hl=en&sjid=864417124752637253-EU"
    Runbook = "Investigate the behavior that got the account suspended. Verify with the user that this intended behavior. If not, the account may have been compromised.\n"
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_user_suspended_tests
    USER_SUSPENDED_EVENTS = {
        "account_disabled_generic",
        "account_disabled_spamming_through_relay",
        "account_disabled_spamming",
        "account_disabled_hijacked",
    }

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "login":
            return False
        return bool(event.get("name") in self.USER_SUSPENDED_EVENTS)

    def title(self, event):
        user = deep_get(event, "parameters", "affected_email_address")
        if not user:
            user = "<UNKNOWN_USER>"
        return f"User [{user}]'s account was disabled"
