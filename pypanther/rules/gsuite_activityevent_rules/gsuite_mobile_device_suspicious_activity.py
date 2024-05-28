from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

g_suite_device_suspicious_activity_tests: List[PantherRuleTest] = [
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
        Name="Suspicious Activity",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "mobile"},
            "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
            "type": "device_updates",
            "name": "SUSPICIOUS_ACTIVITY_EVENT",
            "parameters": {"USER_EMAIL": "homer.simpson@example.io"},
        },
    ),
]


class GSuiteDeviceSuspiciousActivity(PantherRule):
    RuleID = "GSuite.DeviceSuspiciousActivity-prototype"
    DisplayName = "GSuite Device Suspicious Activity"
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite"]
    Severity = PantherSeverity.Low
    Description = "GSuite reported a suspicious activity on a user's device.\n"
    Reference = "https://support.google.com/a/answer/7562460?hl=en&sjid=864417124752637253-EU"
    Runbook = "Validate that the suspicious activity was expected by the user.\n"
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_device_suspicious_activity_tests

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "mobile":
            return False
        return bool(event.get("name") == "SUSPICIOUS_ACTIVITY_EVENT")

    def title(self, event):
        return f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}]'s device was compromised"
