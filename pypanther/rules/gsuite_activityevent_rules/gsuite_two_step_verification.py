from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

g_suite_two_step_verification_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Two Step Verification Enabled",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "user_accounts"},
            "actor": {"callerType": "USER", "email": "some.user@somedomain.com"},
            "kind": "admin#reports#activity",
            "type": "2sv_change",
            "name": "2sv_enroll",
        },
    ),
    PantherRuleTest(
        Name="Two Step Verification Disabled",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "user_accounts"},
            "actor": {"callerType": "USER", "email": "some.user@somedomain.com"},
            "kind": "admin#reports#activity",
            "type": "2sv_change",
            "name": "2sv_disable",
        },
    ),
]


class GSuiteTwoStepVerification(PantherRule):
    RuleID = "GSuite.TwoStepVerification-prototype"
    DisplayName = "GSuite User Two Step Verification Change"
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite", "Defense Evasion:Modify Authentication Process"]
    Reports = {"MITRE ATT&CK": ["TA0005:T1556"]}
    Severity = PantherSeverity.Low
    Description = "A user disabled two step verification for themselves.\n"
    Reference = "https://support.google.com/mail/answer/185839?hl=en&co=GENIE.Platform%3DDesktop&sjid=864417124752637253-EU"
    Runbook = "Depending on company policy, either suggest or require the user re-enable two step verification.\n"
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_two_step_verification_tests

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "user_accounts":
            return False
        if event.get("type") == "2sv_change" and event.get("name") == "2sv_disable":
            return True
        return False

    def title(self, event):
        return f"Two step verification was disabled for user [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}]"
