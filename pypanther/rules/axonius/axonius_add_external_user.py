from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class AxoniusAddExternalUser(Rule):
    id = "Axonius.AddExternalUser-prototype"
    display_name = "Axonius External User Added"
    log_types = [LogType.AXONIUS_ACTIVITY]
    tags = ["Axonius"]
    default_severity = Severity.LOW
    default_description = "Detects when an external user is added in Axonius"
    default_runbook = "Review if the external user is authorized"

    def rule(self, event):
        action = event.deep_get("event", "action", default="")
        category = event.deep_get("event", "category", default="")
        if action == "AuditAction.AddExternalUser" and category == "AuditCategory.UserManagement":
            return True
        return False

    def title(self, event):
        username = event.deep_get("event", "params", "user_name", default="")
        source = event.deep_get("event", "params", "source", default="")
        return f"[Axonius] External User {username} added from {source}"

    def alert_context(self, event):
        username = event.deep_get("event", "params", "user_name", default="")
        source = event.deep_get("event", "params", "source", default="")
        context = {"username": username, "source": source}
        return context

    tests = [
        RuleTest(
            name="External User Created",
            expected_result=True,
            log={
                "event": {
                    "action": "AuditAction.AddExternalUser",
                    "category": "AuditCategory.UserManagement",
                    "params": {"source": "SAM-XYX", "user_name": "external-user@axonius.com"},
                    "type": "info",
                },
                "source": "axonius",
                "time": 1747795144.253623,
            },
        ),
    ]
