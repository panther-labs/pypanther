from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

duo_user_action_fraudulent_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="user_marked_fraud",
        ExpectedResult=True,
        Log={
            "access_device": {"ip": "12.12.112.25", "os": "Mac OS X"},
            "auth_device": {"ip": "12.12.12.12"},
            "application": {"key": "D12345", "name": "Slack"},
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "user_marked_fraud",
            "result": "fraud",
            "user": {"name": "example@example.io"},
        },
    )
]


class DUOUserActionFraudulent(PantherRule):
    RuleID = "DUO.User.Action.Fraudulent-prototype"
    DisplayName = "Duo User Action Reported as Fraudulent"
    DedupPeriodMinutes = 15
    LogTypes = [LogType.Duo_Authentication]
    Tags = ["Duo"]
    Severity = PantherSeverity.Medium
    Description = "Alert when a user reports a Duo action as fraudulent.\n"
    Reference = "https://duo.com/docs/adminapi#authentication-logs"
    Runbook = "Follow up with the user to confirm."
    Tests = duo_user_action_fraudulent_tests

    def rule(self, event):
        return event.get("result") == "fraud"

    def title(self, event):
        user = deep_get(event, "user", "name", default="Unknown")
        return f"A Duo action was marked as fraudulent by [{user}]"

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
