from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

g_suite_device_unlock_failure_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Normal Mobile Event",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "mobile"},
            "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
            "type": "device_updates",
            "name": "DEVICE_SYNC_EVENT",
            "parameters": {"USER_EMAIL": "homer.simpson@example.io"},
        },
    ),
    PantherRuleTest(
        Name="Small Number of Failed Logins",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "mobile"},
            "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
            "type": "device_updates",
            "name": "FAILED_PASSWORD_ATTEMPTS_EVENT",
            "parameters": {"USER_EMAIL": "homer.simpson@example.io", "FAILED_PASSWD_ATTEMPTS": 2},
        },
    ),
    PantherRuleTest(
        Name="Multiple Failed Login Attempts with int Type",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "mobile"},
            "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
            "type": "device_updates",
            "name": "FAILED_PASSWORD_ATTEMPTS_EVENT",
            "parameters": {"USER_EMAIL": "homer.simpson@example.io", "FAILED_PASSWD_ATTEMPTS": 100},
        },
    ),
    PantherRuleTest(
        Name="Multiple Failed Login Attempts with String Type",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "mobile"},
            "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
            "type": "device_updates",
            "name": "FAILED_PASSWORD_ATTEMPTS_EVENT",
            "parameters": {
                "USER_EMAIL": "homer.simpson@example.io",
                "FAILED_PASSWD_ATTEMPTS": "100",
            },
        },
    ),
]


class GSuiteDeviceUnlockFailure(PantherRule):
    RuleID = "GSuite.DeviceUnlockFailure-prototype"
    DisplayName = "GSuite User Device Unlock Failures"
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite", "Credential Access:Brute Force"]
    Reports = {"MITRE ATT&CK": ["TA0006:T1110"]}
    Severity = PantherSeverity.Medium
    Description = "Someone failed to unlock a user's device multiple times in quick succession.\n"
    Reference = "https://support.google.com/a/answer/6350074?hl=en"
    Runbook = "Verify that these unlock attempts came from the user, and not a malicious actor which has acquired the user's device.\n"
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_device_unlock_failure_tests
    MAX_UNLOCK_ATTEMPTS = 10

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "mobile":
            return False
        if event.get("name") == "FAILED_PASSWORD_ATTEMPTS_EVENT":
            attempts = deep_get(event, "parameters", "FAILED_PASSWD_ATTEMPTS")
            return int(attempts if attempts else 0) > self.MAX_UNLOCK_ATTEMPTS
        return False

    def title(self, event):
        return f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}]'s device had multiple failed unlock attempts"
