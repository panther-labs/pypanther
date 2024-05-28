from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

g_suite_advanced_protection_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Advanced Protection Enabled",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "user_accounts"},
            "actor": {"callerType": "USER", "email": "homer.simpson@example.com"},
            "type": "titanium_change",
            "name": "titanium_enroll",
        },
    ),
    PantherRuleTest(
        Name="Advanced Protection Disabled",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "user_accounts"},
            "actor": {"callerType": "USER", "email": "homer.simpson@example.com"},
            "type": "titanium_change",
            "name": "titanium_unenroll",
        },
    ),
]


class GSuiteAdvancedProtection(PantherRule):
    RuleID = "GSuite.AdvancedProtection-prototype"
    DisplayName = "GSuite User Advanced Protection Change"
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite", "Defense Evasion:Impair Defenses"]
    Reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    Severity = PantherSeverity.Low
    Description = "A user disabled advanced protection for themselves.\n"
    Reference = "https://support.google.com/a/answer/9378686?hl=en&sjid=864417124752637253-EU"
    Runbook = "Have the user re-enable Google Advanced Protection\n"
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_advanced_protection_tests

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "user_accounts":
            return False
        return bool(event.get("name") == "titanium_unenroll")

    def title(self, event):
        return f"Advanced protection was disabled for user [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}]"
