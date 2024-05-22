from typing import List
from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_base_helpers import deep_get

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
    Enabled = True
    LogTypes = ["GSuite.ActivityEvent"]
    Tags = ["GSuite"]
    Severity = Severity.Low
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
