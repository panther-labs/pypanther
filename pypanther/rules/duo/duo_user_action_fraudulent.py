from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


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

    def rule(self, event):
        return event.get("result") == "fraud"

    def title(self, event):
        user = event.deep_get("user", "name", default="Unknown")
        return f"A Duo action was marked as fraudulent by [{user}]"

    def alert_context(self, event):
        return {
            "factor": event.get("factor"),
            "reason": event.get("reason"),
            "user": event.deep_get("user", "name", default=""),
            "os": event.deep_get("access_device", "os", default=""),
            "ip_access": event.deep_get("access_device", "ip", default=""),
            "ip_auth": event.deep_get("auth_device", "ip", default=""),
            "application": event.deep_get("application", "name", default=""),
        }

    tests = [
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
