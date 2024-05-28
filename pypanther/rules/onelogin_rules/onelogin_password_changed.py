from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

one_login_password_changed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="User changed their password",
        ExpectedResult=True,
        Log={
            "event_type_id": "11",
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
    PantherRuleTest(
        Name="User changed another's password",
        ExpectedResult=True,
        Log={
            "event_type_id": "11",
            "actor_user_id": 654321,
            "actor_user_name": "Mountain Lion",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
    PantherRuleTest(
        Name="Admin user changed another's password",
        ExpectedResult=False,
        Log={
            "event_type_id": "211",
            "actor_user_id": 654321,
            "actor_user_name": "Mountain Lion",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
]


class OneLoginPasswordChanged(PantherRule):
    RuleID = "OneLogin.PasswordChanged-prototype"
    DisplayName = "OneLogin User Password Changed"
    LogTypes = [LogType.OneLogin_Events]
    Tags = ["OneLogin", "Identity & Access Management"]
    Severity = PantherSeverity.Info
    Description = "A user password was updated.\n"
    Reference = "https://onelogin.service-now.com/kb_view_customer.do?sysparm_article=KB0010510"
    Runbook = "Investigate whether this was an authorized action.\n"
    SummaryAttributes = ["account_id", "user_name", "user_id"]
    Tests = one_login_password_changed_tests

    def rule(self, event):
        # check that this is a password change event;
        # event id 11 is actor_user changed password for user
        # Normally, admin's may change a user's password (event id 211)
        return str(event.get("event_type_id")) == "11"

    def title(self, event):
        return f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] password changed by user [{event.get('actor_user_name', '<UNKNOWN_USER>')}]"
