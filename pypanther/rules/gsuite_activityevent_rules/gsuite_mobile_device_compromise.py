from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

g_suite_device_compromise_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Normal Mobile Event",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "mobile"},
            "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
            "type": "device_updates",
            "name": "DEVICE_REGISTER_UNREGISTER_EVENT",
            "parameters": {"USER_EMAIL": "homer.simpson@example.io"},
        },
    ),
    PantherRuleTest(
        Name="Suspicious Activity Shows not Compromised",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "mobile"},
            "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
            "type": "device_updates",
            "name": "DEVICE_COMPROMISED_EVENT",
            "parameters": {
                "USER_EMAIL": "homer.simpson@example.io",
                "DEVICE_COMPROMISED_STATE": "NOT_COMPROMISED",
            },
        },
    ),
    PantherRuleTest(
        Name="Suspicious Activity Shows Compromised",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "mobile"},
            "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
            "type": "device_updates",
            "name": "DEVICE_COMPROMISED_EVENT",
            "parameters": {
                "USER_EMAIL": "homer.simpson@example.io",
                "DEVICE_COMPROMISED_STATE": "COMPROMISED",
            },
        },
    ),
]


class GSuiteDeviceCompromise(PantherRule):
    RuleID = "GSuite.DeviceCompromise-prototype"
    DisplayName = "GSuite User Device Compromised"
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite"]
    Severity = PantherSeverity.Medium
    Description = "GSuite reported a user's device has been compromised.\n"
    Reference = "https://support.google.com/a/answer/7562165?hl=en&sjid=864417124752637253-EU"
    Runbook = "Have the user change their passwords and reset the device.\n"
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_device_compromise_tests

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "mobile":
            return False
        if event.get("name") == "DEVICE_COMPROMISED_EVENT":
            return bool(deep_get(event, "parameters", "DEVICE_COMPROMISED_STATE") == "COMPROMISED")
        return False

    def title(self, event):
        return f"User [{deep_get(event, 'parameters', 'USER_EMAIL', default='<UNKNOWN_USER>')}]'s device was compromised"
