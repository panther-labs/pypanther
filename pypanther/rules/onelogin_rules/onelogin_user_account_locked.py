from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

one_login_user_account_locked_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="User account locked via api - first method.",
        ExpectedResult=True,
        Log={
            "event_type_id": "531",
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
    PantherRuleTest(
        Name="User account locked via api - second method.",
        ExpectedResult=True,
        Log={
            "event_type_id": "553",
            "actor_user_id": 654321,
            "actor_user_name": "Mountain Lion",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
    PantherRuleTest(
        Name="User account suspended via api.",
        ExpectedResult=True,
        Log={
            "event_type_id": "551",
            "actor_user_id": 654321,
            "actor_user_name": "Mountain Lion",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
    PantherRuleTest(
        Name="Normal User Activated Event",
        ExpectedResult=False,
        Log={
            "event_type_id": "11",
            "actor_user_id": 654321,
            "actor_user_name": "Mountain Lion",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
]


class OneLoginUserAccountLocked(PantherRule):
    RuleID = "OneLogin.UserAccountLocked-prototype"
    DisplayName = "OneLogin User Locked"
    LogTypes = [LogType.OneLogin_Events]
    Tags = ["OneLogin", "Credential Access:Brute Force"]
    Reports = {"MITRE ATT&CK": ["TA0006:T1110"]}
    Severity = PantherSeverity.Low
    Description = "User locked or suspended from their account.\n"
    Reference = "https://onelogin.service-now.com/kb_view_customer.do?sysparm_article=KB0010420"
    Runbook = "Investigate whether this was caused by expected action.\n"
    SummaryAttributes = ["account_id", "event_type_id", "user_name", "user_id"]
    Tests = one_login_user_account_locked_tests

    def rule(self, event):
        # check for a user locked event
        # event 531 and 553 are user lock events via api
        # event 551 is user suspended via api
        return str(event.get("event_type_id")) in ["531", "553", "551"]

    def title(self, event):
        return f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] was locked or suspended via api call"
