from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class AxoniusResetApiKey(Rule):
    id = "Axonius.ResetApiKey-prototype"
    display_name = "Axonius API Key Reset"
    log_types = [LogType.AXONIUS_ACTIVITY]
    tags = ["Axonius"]
    default_severity = Severity.LOW
    default_description = "Detects an Axonius API Key Reset"
    default_runbook = "Review the actions taken, check credentials/service user used and escalate."

    def rule(self, event):
        action = event.deep_get("event", "action", default="")
        if action == "AuditAction.ResetApiKey":
            return True
        return False

    def title(self, event):
        username = event.deep_get("event", "user", default="")
        return f"[Axonius] API Key Reset for {username} Detected"

    tests = [
        RuleTest(
            name="API Key Reset",
            expected_result=True,
            log={
                "event": {
                    "action": "AuditAction.ResetApiKey",
                    "category": "AuditCategory.Settings",
                    "params": {},
                    "type": "user",
                    "user": "boss@axonius.com",
                },
                "source": "axonius",
                "time": 1752699243.486779,
            },
        ),
    ]
