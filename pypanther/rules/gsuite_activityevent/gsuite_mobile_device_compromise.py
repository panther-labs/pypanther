from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GSuiteDeviceCompromise(Rule):
    id = "GSuite.DeviceCompromise-prototype"
    display_name = "GSuite User Device Compromised"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite"]
    default_severity = Severity.MEDIUM
    default_description = "GSuite reported a user's device has been compromised.\n"
    default_reference = "https://support.google.com/a/answer/7562165?hl=en&sjid=864417124752637253-EU"
    default_runbook = "Have the user change their passwords and reset the device.\n"
    summary_attributes = ["actor:email"]

    def rule(self, event):
        if event.deep_get("id", "applicationName") != "mobile":
            return False
        if event.get("name") == "DEVICE_COMPROMISED_EVENT":
            return bool(event.deep_get("parameters", "DEVICE_COMPROMISED_STATE") == "COMPROMISED")
        return False

    def title(self, event):
        return f"User [{event.deep_get('parameters', 'USER_EMAIL', default='<UNKNOWN_USER>')}]'s device was compromised"

    tests = [
        RuleTest(
            name="Normal Mobile Event",
            expected_result=False,
            log={
                "id": {"applicationName": "mobile"},
                "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
                "type": "device_updates",
                "name": "DEVICE_REGISTER_UNREGISTER_EVENT",
                "parameters": {"USER_EMAIL": "homer.simpson@example.io"},
            },
        ),
        RuleTest(
            name="Suspicious Activity Shows not Compromised",
            expected_result=False,
            log={
                "id": {"applicationName": "mobile"},
                "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
                "type": "device_updates",
                "name": "DEVICE_COMPROMISED_EVENT",
                "parameters": {"USER_EMAIL": "homer.simpson@example.io", "DEVICE_COMPROMISED_STATE": "NOT_COMPROMISED"},
            },
        ),
        RuleTest(
            name="Suspicious Activity Shows Compromised",
            expected_result=True,
            log={
                "id": {"applicationName": "mobile"},
                "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
                "type": "device_updates",
                "name": "DEVICE_COMPROMISED_EVENT",
                "parameters": {"USER_EMAIL": "homer.simpson@example.io", "DEVICE_COMPROMISED_STATE": "COMPROMISED"},
            },
        ),
    ]
