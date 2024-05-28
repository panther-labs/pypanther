from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

duo_user_bypass_code_used_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="bypass_code_used",
        ExpectedResult=True,
        Log={
            "access_device": {"ip": "12.12.112.25", "os": "Mac OS X"},
            "auth_device": {"ip": "12.12.12.12"},
            "application": {"key": "D12345", "name": "Slack"},
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "bypass_user",
            "result": "success",
            "user": {"name": "example@example.io"},
        },
    ),
    PantherRuleTest(
        Name="good_auth",
        ExpectedResult=False,
        Log={
            "access_device": {"ip": "12.12.112.25", "os": "Mac OS X"},
            "auth_device": {"ip": "12.12.12.12"},
            "application": {"key": "D12345", "name": "Slack"},
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "user_approved",
            "result": "success",
            "user": {"name": "example@example.io"},
        },
    ),
    PantherRuleTest(
        Name="denied_old_creds",
        ExpectedResult=False,
        Log={
            "access_device": {"ip": "12.12.112.25", "os": "Mac OS X"},
            "auth_device": {"ip": "12.12.12.12"},
            "application": {"key": "D12345", "name": "Slack"},
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "out_of_date",
            "result": "denied",
            "user": {"name": "example@example.io"},
        },
    ),
]


class DUOUserBypassCodeUsed(PantherRule):
    RuleID = "DUO.User.BypassCode.Used-prototype"
    DisplayName = "Duo User Bypass Code Used"
    DedupPeriodMinutes = 5
    LogTypes = [LogType.Duo_Authentication]
    Tags = ["Duo"]
    Severity = PantherSeverity.Low
    Description = "A Duo user's bypass code was used to authenticate"
    Reference = "https://duo.com/docs/adminapi#authentication-logs"
    Runbook = "Follow up with the user to confirm they used the bypass code themselves."
    Tests = duo_user_bypass_code_used_tests

    def rule(self, event):
        return event.get("reason") == "bypass_user" and event.get("result") == "success"

    def title(self, event):
        user = deep_get(event, "user", "name", default="Unknown")
        return f"Bypass code for Duo User [{user}] used"

    def alert_context(self, event):
        return {
            "factor": event.get("factor"),
            "reason": event.get("reason"),
            "user": deep_get(event, "user", "name", default=""),
            "os": deep_get(event, "access_device", "os", default=""),
            "ip_access": deep_get(event, "access_device", "ip", default=""),
            "ip_auth": deep_get(event, "auth_device", "ip", default=""),
            "application": deep_get(event, "application", "name", default=""),
        }
