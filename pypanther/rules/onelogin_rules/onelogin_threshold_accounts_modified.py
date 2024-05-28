from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

one_login_threshold_accounts_modified_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Normal User Activated Event",
        ExpectedResult=False,
        Log={
            "event_type_id": "16",
            "actor_user_id": 654321,
            "actor_user_name": "Mountain Lion",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
    PantherRuleTest(
        Name="User Password Changed Event",
        ExpectedResult=True,
        Log={
            "event_type_id": "11",
            "actor_user_id": 654321,
            "actor_user_name": "Mountain Lion",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
]


class OneLoginThresholdAccountsModified(PantherRule):
    RuleID = "OneLogin.ThresholdAccountsModified-prototype"
    DisplayName = "OneLogin Multiple Accounts Modified"
    LogTypes = [LogType.OneLogin_Events]
    Tags = ["OneLogin", "Impact:Account Access Removal"]
    Severity = PantherSeverity.Medium
    Reports = {"MITRE ATT&CK": ["TA0040:T1531"]}
    Description = "Possible Denial of Service detected. Threshold for user account password changes exceeded.\n"
    Threshold = 10
    DedupPeriodMinutes = 10
    Reference = "https://en.wikipedia.org/wiki/Denial-of-service_attack"
    Runbook = "Determine if this is normal user-cleanup activity."
    SummaryAttributes = ["account_id", "user_name", "user_id"]
    Tests = one_login_threshold_accounts_modified_tests

    def rule(self, event):
        # filter events; event type 11 is an actor_user changed user password
        return str(event.get("event_type_id")) == "11"

    def title(self, event):
        return f"User [{event.get('actor_user_name', '<UNKNOWN_USER>')}] has exceeded the user account password change threshold"
