from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

duo_admin_bypass_code_viewed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Bypass View",
        ExpectedResult=True,
        Log={
            "action": "bypass_view",
            "description": '{"user_id": "D1234", "bypass_code_id": "D5678"}',
            "isotimestamp": "2022-12-14 21:17:54",
            "object": "target@example.io",
            "timestamp": "2022-12-14 21:17:54",
            "username": "Homer Simpson",
        },
    ),
    PantherRuleTest(
        Name="Bypass Create",
        ExpectedResult=False,
        Log={
            "action": "bypass_create",
            "description": '{"bypass": "", "count": 1, "valid_secs": 3600, "auto_generated": true, "remaining_uses": 1, "user_id": "D12345", "bypass_code_ids": ["A12345"]}',
            "isotimestamp": "2022-12-14 21:17:39",
            "object": "target@example.io",
            "timestamp": "2022-12-14 21:17:39",
            "username": "Homer Simpson",
        },
    ),
]


class DuoAdminBypassCodeViewed(PantherRule):
    Description = "An administrator viewed the MFA bypass code for a user."
    DisplayName = "Duo Admin Bypass Code Viewed"
    Reference = "https://duo.com/docs/adminapi"
    Runbook = "Confirm this behavior is authorized. The security of your Duo application is tied to the security of your secret key (skey). Secure it as you would any sensitive credential. You should not share it with unauthorized individuals or email it to anyone under any circumstances!"
    Severity = PantherSeverity.Medium
    LogTypes = [LogType.Duo_Administrator]
    RuleID = "Duo.Admin.Bypass.Code.Viewed-prototype"
    Tests = duo_admin_bypass_code_viewed_tests

    def rule(self, event):
        # Return True to match the log event and trigger an alert.
        return event.get("action", "") == "bypass_view"

    def title(self, event):
        # If no 'dedup' function is defined, the return value
        # of this method will act as deduplication string.
        return f"Duo: [{event.get('username', '<NO_USER_FOUND>')}] viewed an MFA bypass code for [{event.get('object', '<NO_OBJECT_FOUND>')}]."
