from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GSuiteDeviceSuspiciousActivity(Rule):
    id = "GSuite.DeviceSuspiciousActivity-prototype"
    display_name = "GSuite Device Suspicious Activity"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite"]
    default_severity = Severity.LOW
    default_description = "GSuite reported a suspicious activity on a user's device.\n"
    default_reference = "https://support.google.com/a/answer/7562460?hl=en&sjid=864417124752637253-EU"
    default_runbook = "Validate that the suspicious activity was expected by the user.\n"
    summary_attributes = ["actor:email"]

    def rule(self, event):
        if event.deep_get("id", "applicationName") != "mobile":
            return False
        return bool(event.get("name") == "SUSPICIOUS_ACTIVITY_EVENT")

    def title(self, event):
        return f"User [{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}]'s device was compromised"

    tests = [
        RuleTest(
            name="Normal Mobile Event",
            expected_result=False,
            log={
                "id": {"applicationName": "mobile"},
                "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
                "type": "device_updates",
                "name": "DEVICE_SYNC_EVENT",
                "parameters": {"USER_EMAIL": "homer.simpson@example.io"},
            },
        ),
        RuleTest(
            name="Suspicious Activity",
            expected_result=True,
            log={
                "id": {"applicationName": "mobile"},
                "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
                "type": "device_updates",
                "name": "SUSPICIOUS_ACTIVITY_EVENT",
                "parameters": {"USER_EMAIL": "homer.simpson@example.io"},
            },
        ),
    ]
