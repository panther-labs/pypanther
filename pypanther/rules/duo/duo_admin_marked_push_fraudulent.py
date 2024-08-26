from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_duo_helpers import deserialize_administrator_log_event_description

duo_admin_action_marked_fraudulent_tests: list[RuleTest] = [
    RuleTest(
        name="marked_fraud",
        expected_result=True,
        log={
            "action": "admin_2fa_error",
            "description": '{"ip_address": "12.12.12.12", "email": "example@example.io", "factor": "push", "error": "Login request reported as fraudulent."}',
            "isotimestamp": "2022-12-14 20:11:53",
            "timestamp": "2022-12-14 20:11:53",
            "username": "John P. Admin",
        },
    ),
    RuleTest(
        name="different_admin_action",
        expected_result=False,
        log={
            "action": "admin_update",
            "description": "{}",
            "isotimestamp": "2022-12-14 20:11:53",
            "timestamp": "2022-12-14 20:11:53",
            "username": "John P. Admin",
        },
    ),
]


@panther_managed
class DUOAdminActionMarkedFraudulent(Rule):
    id = "DUO.Admin.Action.MarkedFraudulent-prototype"
    display_name = "Duo Admin Marked Push Fraudulent"
    dedup_period_minutes = 15
    log_types = [LogType.DUO_ADMINISTRATOR]
    tags = ["Duo"]
    default_severity = Severity.MEDIUM
    default_description = "A Duo push was marked fraudulent by an admin."
    default_reference = "https://duo.com/docs/adminapi#administrator-logs"
    default_runbook = "Follow up with the administrator to determine reasoning for marking fraud."
    tests = duo_admin_action_marked_fraudulent_tests

    def rule(self, event):
        event_description = deserialize_administrator_log_event_description(event)
        return event.get("action") == "admin_2fa_error" and "fraudulent" in event_description.get("error", "").lower()

    def title(self, event):
        event_description = deserialize_administrator_log_event_description(event)
        admin_username = event.get("username", "Unknown")
        user_email = event_description.get("email", "Unknown")
        return f"Duo Admin [{admin_username}] denied due to an anomalous 2FA push for [{user_email}]"

    def alert_context(self, event):
        event_description = deserialize_administrator_log_event_description(event)
        return {
            "reason": event_description.get("error", ""),
            "reporting_admin": event.get("username", ""),
            "user": event_description.get("email", ""),
            "ip_address": event_description.get("ip_address", ""),
        }
