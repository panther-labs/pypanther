from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

duo_admin_bypass_code_created_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Bypass Create",
        ExpectedResult=True,
        Log={
            "action": "bypass_create",
            "description": '{"bypass": "", "count": 1, "valid_secs": 3600, "auto_generated": true, "remaining_uses": 1, "user_id": "D12345", "bypass_code_ids": ["A12345"]}',
            "isotimestamp": "2022-12-14 21:17:39",
            "object": "target@example.io",
            "timestamp": "2022-12-14 21:17:39",
            "username": "Homer Simpson",
        },
    ),
    PantherRuleTest(
        Name="Bypass Delete",
        ExpectedResult=False,
        Log={
            "action": "bypass_detele",
            "description": '{"bypass": "", "count": 1, "valid_secs": 3600, "auto_generated": true, "remaining_uses": 1, "user_id": "D12345", "bypass_code_ids": ["A12345"]}',
            "isotimestamp": "2022-12-14 21:17:39",
            "object": "target@example.io",
            "timestamp": "2022-12-14 21:17:39",
            "username": "Homer Simpson",
        },
    ),
]


class DuoAdminBypassCodeCreated(PantherRule):
    Description = "A Duo administrator created an MFA bypass code for an application."
    DisplayName = "Duo Admin Bypass Code Created"
    Runbook = "Confirm this was authorized and necessary behavior."
    Reference = "https://duo.com/docs/administration-users#generating-a-bypass-code"
    Severity = PantherSeverity.Medium
    LogTypes = [LogType.Duo_Administrator]
    RuleID = "Duo.Admin.Bypass.Code.Created-prototype"
    Tests = duo_admin_bypass_code_created_tests

    def rule(self, event):
        # Return True to match the log event and trigger an alert.
        return event.get("action", "") == "bypass_create"

    def title(self, event):
        # If no 'dedup' function is defined, the return value of
        # this method will act as deduplication string.
        return f"Duo: [{event.get('username', '<NO_USER_FOUND>')}] created a MFA bypass code for [{event.get('object', '<NO_OBJECT_FOUND>')}]"
