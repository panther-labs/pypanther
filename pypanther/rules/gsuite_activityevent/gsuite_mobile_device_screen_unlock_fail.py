from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GSuiteDeviceUnlockFailure(Rule):
    id = "GSuite.DeviceUnlockFailure-prototype"
    display_name = "GSuite User Device Unlock Failures"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite", "Credential Access:Brute Force"]
    reports = {"MITRE ATT&CK": ["TA0006:T1110"]}
    default_severity = Severity.MEDIUM
    default_description = "Someone failed to unlock a user's device multiple times in quick succession.\n"
    default_reference = "https://support.google.com/a/answer/6350074?hl=en"
    default_runbook = "Verify that these unlock attempts came from the user, and not a malicious actor which has acquired the user's device.\n"
    summary_attributes = ["actor:email"]
    MAX_UNLOCK_ATTEMPTS = 10

    def rule(self, event):
        if event.deep_get("id", "applicationName") != "mobile":
            return False
        if event.get("name") == "FAILED_PASSWORD_ATTEMPTS_EVENT":
            attempts = event.deep_get("parameters", "FAILED_PASSWD_ATTEMPTS")
            return int(attempts if attempts else 0) > self.MAX_UNLOCK_ATTEMPTS
        return False

    def title(self, event):
        return f"User [{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}]'s device had multiple failed unlock attempts"

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
            name="Small Number of Failed Logins",
            expected_result=False,
            log={
                "id": {"applicationName": "mobile"},
                "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
                "type": "device_updates",
                "name": "FAILED_PASSWORD_ATTEMPTS_EVENT",
                "parameters": {"USER_EMAIL": "homer.simpson@example.io", "FAILED_PASSWD_ATTEMPTS": 2},
            },
        ),
        RuleTest(
            name="Multiple Failed Login Attempts with int Type",
            expected_result=True,
            log={
                "id": {"applicationName": "mobile"},
                "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
                "type": "device_updates",
                "name": "FAILED_PASSWORD_ATTEMPTS_EVENT",
                "parameters": {"USER_EMAIL": "homer.simpson@example.io", "FAILED_PASSWD_ATTEMPTS": 100},
            },
        ),
        RuleTest(
            name="Multiple Failed Login Attempts with String Type",
            expected_result=True,
            log={
                "id": {"applicationName": "mobile"},
                "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
                "type": "device_updates",
                "name": "FAILED_PASSWORD_ATTEMPTS_EVENT",
                "parameters": {"USER_EMAIL": "homer.simpson@example.io", "FAILED_PASSWD_ATTEMPTS": "100"},
            },
        ),
    ]
