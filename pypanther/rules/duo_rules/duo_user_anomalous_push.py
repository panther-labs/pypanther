from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

duo_user_denied_anomalous_push_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="anomalous_push_occurred",
        ExpectedResult=True,
        Log={
            "access_device": {"ip": "12.12.112.25", "os": "Mac OS X"},
            "auth_device": {"ip": "12.12.12.12"},
            "application": {"key": "D12345", "name": "Slack"},
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "anomalous_push",
            "result": "denied",
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


class DUOUserDeniedAnomalousPush(PantherRule):
    RuleID = "DUO.User.Denied.AnomalousPush-prototype"
    DisplayName = "Duo User Auth Denied For Anomalous Push"
    DedupPeriodMinutes = 15
    LogTypes = [LogType.Duo_Authentication]
    Tags = ["Duo"]
    Severity = PantherSeverity.Medium
    Description = "A Duo authentication was denied due to an anomalous 2FA push.\n"
    Reference = "https://duo.com/docs/adminapi#authentication-logs"
    Runbook = "Follow up with the user to confirm they intended several pushes in quick succession."
    Tests = duo_user_denied_anomalous_push_tests

    def rule(self, event):
        return event.get("reason") == "anomalous_push" and event.get("result") == "denied"

    def title(self, event):
        user = deep_get(event, "user", "name", default="Unknown")
        return f"Duo Auth denied due to an anomalous 2FA push for [{user}]"

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
