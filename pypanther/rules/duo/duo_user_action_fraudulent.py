from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

duo_user_action_fraudulent_tests: list[RuleTest] = [
    RuleTest(
        name="user_marked_fraud",
        expected_result=True,
        log={
            "access_device": {"ip": "12.12.112.25", "os": "Mac OS X"},
            "auth_device": {"ip": "12.12.12.12"},
            "application": {"key": "D12345", "name": "Slack"},
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "user_marked_fraud",
            "result": "fraud",
            "user": {"name": "example@example.io"},
        },
    ),
]


@panther_managed
class DUOUserActionFraudulent(Rule):
    id = "DUO.User.Action.Fraudulent-prototype"
    display_name = "Duo User Action Reported as Fraudulent"
    dedup_period_minutes = 15
    log_types = [LogType.DUO_AUTHENTICATION]
    tags = ["Duo"]
    default_severity = Severity.MEDIUM
    default_description = "Alert when a user reports a Duo action as fraudulent.\n"
    default_reference = "https://duo.com/docs/adminapi#authentication-logs"
    default_runbook = "Follow up with the user to confirm."
    tests = duo_user_action_fraudulent_tests

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
