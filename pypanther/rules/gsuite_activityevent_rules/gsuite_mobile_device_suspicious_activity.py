from typing import List

from pypanther import PantherLogType, PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get

g_suite_device_suspicious_activity_tests: List[PantherRuleTest] = [
    PantherRuleTest(
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
    PantherRuleTest(
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


class GSuiteDeviceSuspiciousActivity(PantherRule):
    id_ = "GSuite.DeviceSuspiciousActivity-prototype"
    display_name = "GSuite Device Suspicious Activity"
    log_types = [PantherLogType.GSuite_ActivityEvent]
    tags = ["GSuite"]
    default_severity = PantherSeverity.low
    default_description = "GSuite reported a suspicious activity on a user's device.\n"
    default_reference = (
        "https://support.google.com/a/answer/7562460?hl=en&sjid=864417124752637253-EU"
    )
    default_runbook = "Validate that the suspicious activity was expected by the user.\n"
    summary_attributes = ["actor:email"]
    tests = g_suite_device_suspicious_activity_tests

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "mobile":
            return False
        return bool(event.get("name") == "SUSPICIOUS_ACTIVITY_EVENT")

    def title(self, event):
        return f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}]'s device was compromised"
