from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

one_login_user_assumption_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="User assumed their own account",
        ExpectedResult=False,
        Log={
            "event_type_id": "240",
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
    PantherRuleTest(
        Name="User assumed another user's account",
        ExpectedResult=True,
        Log={
            "event_type_id": "3",
            "actor_user_id": 654321,
            "actor_user_name": "Mountain Lion",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
]


class OneLoginUserAssumption(PantherRule):
    RuleID = "OneLogin.UserAssumption-prototype"
    DisplayName = "OneLogin User Assumed Another User"
    LogTypes = [LogType.OneLogin_Events]
    Tags = ["OneLogin", "Lateral Movement:Use Alternate Authentication Material"]
    Reports = {"MITRE ATT&CK": ["TA0008:T1550"]}
    Severity = PantherSeverity.Low
    Description = "User assumed another user account"
    Reference = "https://onelogin.service-now.com/kb_view_customer.do?sysparm_article=KB0010594#:~:text=Prerequisites,Actions%20and%20select%20Assume%20User."
    Runbook = "Investigate whether this was authorized access.\n"
    SummaryAttributes = ["account_id", "user_name", "user_id"]
    Tests = one_login_user_assumption_tests

    def rule(self, event):
        # check that this is a user assumption event; event id 3
        return str(event.get("event_type_id")) == "3" and event.get(
            "actor_user_id", "UNKNOWN_USER"
        ) != event.get("user_id", "UNKNOWN_USER")

    def title(self, event):
        return f"A user [{event.get('actor_user_name', '<UNKNOWN_USER>')}] assumed another user [{event.get('user_name', '<UNKNOWN_USER>')}] account"
