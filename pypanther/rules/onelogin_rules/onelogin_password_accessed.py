from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

one_login_password_access_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="User accessed their own password",
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
        Name="User accessed another user's password",
        ExpectedResult=True,
        Log={
            "event_type_id": "240",
            "actor_user_id": 654321,
            "actor_user_name": "Mountain Lion",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
]


class OneLoginPasswordAccess(PantherRule):
    RuleID = "OneLogin.PasswordAccess-prototype"
    DisplayName = "OneLogin Password Access"
    LogTypes = [LogType.OneLogin_Events]
    Tags = ["OneLogin", "Credential Access:Unsecured Credentials"]
    Reports = {"MITRE ATT&CK": ["TA0006:T1552"]}
    Severity = PantherSeverity.Medium
    Description = "User accessed another user's application password\n"
    Reference = "https://onelogin.service-now.com/kb_view_customer.do?sysparm_article=KB0010598"
    Runbook = "Investigate whether this was authorized access.\n"
    SummaryAttributes = ["account_id", "user_name", "user_id"]
    Tests = one_login_password_access_tests

    def rule(self, event):
        # Filter events; event type 240 is actor_user revealed user's app password
        if (
            str(event.get("event_type_id")) != "240"
            or not event.get("actor_user_id")
            or (not event.get("user_id"))
        ):
            return False
        # Determine if actor_user accessed another user's password
        return event.get("actor_user_id") != event.get("user_id")

    def dedup(self, event):
        return event.get("actor_user_name") + ":" + event.get("app_name", "<UNKNOWN_APP>")

    def title(self, event):
        return f"A user [{event.get('actor_user_name', '<UNKNOWN_USER>')}] accessed another user's [{event.get('user_name', '<UNKNOWN_USER>')}] [{event.get('app_name', '<UNKNOWN_APP>')}] password"
