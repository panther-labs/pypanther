from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class AxoniusWebhookCreated(Rule):
    id = "Axonius.WebhookCreated-prototype"
    display_name = "Axonius Webhook Created"
    log_types = [LogType.AXONIUS_ACTIVITY]
    tags = ["Axonius"]
    default_severity = Severity.LOW
    default_description = "Detects when an Axonius Webhook is Created"
    default_runbook = "Review if the webhook is approved and appropriate"

    def rule(self, event):
        action = event.deep_get("event", "action", default="")
        category = event.deep_get("event", "category", default="")
        if action == "AuditAction.Put" and category == "AuditCategory.WebhookManagement":
            return True
        return False

    def title(self, event):
        username = event.deep_get("event", "user", default="")
        return f"[Axonius] API Key Reset for {username} Detected"

    def alert_context(self, event):
        username = event.deep_get("event", "user", default="")
        config_id = event.deep_get("event", "params", "config_id", default="")
        vendor_name = event.deep_get("event", "params", "vendor_name", default="")
        event_type = event.deep_get("event", "type", default="")
        context = {"username": username, "config_id": config_id, "vendor_name": vendor_name, "type": event_type}
        return context

    tests = [
        RuleTest(
            name="Webhook Created",
            expected_result=True,
            log={
                "event": {
                    "action": "AuditAction.Put",
                    "category": "AuditCategory.WebhookManagement",
                    "params": {"config_id": "66db3fc88a93f66a4da0f084", "vendor_name": "Okta"},
                    "type": "user",
                    "user": "admin@axonius.com",
                },
                "source": "axonius",
                "time": 1745944321.285849,
            },
        ),
    ]
