from typing import List

from pypanther import PantherLogType, PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get

g_suite_device_compromise_tests: List[PantherRuleTest] = [
    PantherRuleTest(
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
    PantherRuleTest(
        name="Suspicious Activity Shows not Compromised",
        expected_result=False,
        log={
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
        name="Suspicious Activity Shows Compromised",
        expected_result=True,
        log={
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
    id_ = "GSuite.DeviceCompromise-prototype"
    display_name = "GSuite User Device Compromised"
    log_types = [PantherLogType.GSuite_ActivityEvent]
    tags = ["GSuite"]
    default_severity = PantherSeverity.medium
    default_description = "GSuite reported a user's device has been compromised.\n"
    default_reference = (
        "https://support.google.com/a/answer/7562165?hl=en&sjid=864417124752637253-EU"
    )
    default_runbook = "Have the user change their passwords and reset the device.\n"
    summary_attributes = ["actor:email"]
    tests = g_suite_device_compromise_tests

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "mobile":
            return False
        if event.get("name") == "DEVICE_COMPROMISED_EVENT":
            return bool(deep_get(event, "parameters", "DEVICE_COMPROMISED_STATE") == "COMPROMISED")
        return False

    def title(self, event):
        return f"User [{deep_get(event, 'parameters', 'USER_EMAIL', default='<UNKNOWN_USER>')}]'s device was compromised"
