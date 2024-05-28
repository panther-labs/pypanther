from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_duo_helpers import deserialize_administrator_log_event_description
from pypanther.log_types import LogType

duo_admin_action_marked_fraudulent_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="marked_fraud",
        ExpectedResult=True,
        Log={
            "action": "admin_2fa_error",
            "description": '{"ip_address": "12.12.12.12", "email": "example@example.io", "factor": "push", "error": "Login request reported as fraudulent."}',
            "isotimestamp": "2022-12-14 20:11:53",
            "timestamp": "2022-12-14 20:11:53",
            "username": "John P. Admin",
        },
    ),
    PantherRuleTest(
        Name="different_admin_action",
        ExpectedResult=False,
        Log={
            "action": "admin_update",
            "description": "{}",
            "isotimestamp": "2022-12-14 20:11:53",
            "timestamp": "2022-12-14 20:11:53",
            "username": "John P. Admin",
        },
    ),
]


class DUOAdminActionMarkedFraudulent(PantherRule):
    RuleID = "DUO.Admin.Action.MarkedFraudulent-prototype"
    DisplayName = "Duo Admin Marked Push Fraudulent"
    DedupPeriodMinutes = 15
    LogTypes = [LogType.Duo_Administrator]
    Tags = ["Duo"]
    Severity = PantherSeverity.Medium
    Description = "A Duo push was marked fraudulent by an admin."
    Reference = "https://duo.com/docs/adminapi#administrator-logs"
    Runbook = "Follow up with the administrator to determine reasoning for marking fraud."
    Tests = duo_admin_action_marked_fraudulent_tests

    def rule(self, event):
        event_description = deserialize_administrator_log_event_description(event)
        return (
            event.get("action") == "admin_2fa_error"
            and "fraudulent" in event_description.get("error", "").lower()
        )

    def title(self, event):
        event_description = deserialize_administrator_log_event_description(event)
        admin_username = event.get("username", "Unknown")
        user_email = event_description.get("email", "Unknown")
        return (
            f"Duo Admin [{admin_username}] denied due to an anomalous 2FA push for [{user_email}]"
        )

    def alert_context(self, event):
        event_description = deserialize_administrator_log_event_description(event)
        return {
            "reason": event_description.get("error", ""),
            "reporting_admin": event.get("username", ""),
            "user": event_description.get("email", ""),
            "ip_address": event_description.get("ip_address", ""),
        }
