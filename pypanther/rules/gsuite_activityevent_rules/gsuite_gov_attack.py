from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

g_suite_government_backed_attack_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Normal Login Event",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "login"},
            "actor": {"email": "homer.simpson@example.com"},
            "type": "login",
            "name": "login_success",
            "parameters": {"is_suspicious": None, "login_challenge_method": ["none"]},
        },
    ),
    PantherRuleTest(
        Name="Government Backed Attack Warning",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "login"},
            "actor": {"email": "homer.simpson@example.com"},
            "type": "login",
            "name": "gov_attack_warning",
            "parameters": {"is_suspicious": None, "login_challenge_method": ["none"]},
        },
    ),
]


class GSuiteGovernmentBackedAttack(PantherRule):
    RuleID = "GSuite.GovernmentBackedAttack-prototype"
    DisplayName = "GSuite Government Backed Attack"
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite"]
    Severity = PantherSeverity.Critical
    Description = (
        "GSuite reported that it detected a government backed attack against your account.\n"
    )
    Reference = "https://support.google.com/a/answer/9007870?hl=en"
    Runbook = "Followup with GSuite support for more details.\n"
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_government_backed_attack_tests

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "login":
            return False
        return bool(event.get("name") == "gov_attack_warning")

    def title(self, event):
        return f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}] may have been targeted by a government attack"
