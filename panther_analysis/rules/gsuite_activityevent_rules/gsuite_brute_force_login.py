from typing import List

from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_base_helpers import deep_get

g_suite_brute_force_login_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Failed Login",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "login"},
            "actor": {"email": "some.user@somedomain.com"},
            "type": "login",
            "name": "login_failure",
        },
    ),
    PantherRuleTest(
        Name="Successful Login",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "login"},
            "actor": {"email": "some.user@somedomain.com"},
            "type": "login",
            "name": "login_success",
        },
    ),
    PantherRuleTest(
        Name="Other Login Event",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "login"},
            "actor": {"email": "some.user@somedomain.com"},
            "type": "login",
            "name": "login_verification",
        },
    ),
]


class GSuiteBruteForceLogin(PantherRule):
    RuleID = "GSuite.BruteForceLogin-prototype"
    DisplayName = "--DEPRECATED-- GSuite Brute Force Login"
    Enabled = False
    LogTypes = ["GSuite.ActivityEvent"]
    Tags = ["GSuite"]
    Severity = Severity.Medium
    Threshold = 10
    DedupPeriodMinutes = 10
    Description = "A GSuite user was denied login access several times"
    Reference = "https://support.google.com/a/answer/7281227?hl=en&sjid=864417124752637253-EU"
    Runbook = "Analyze the IP they came from and actions taken before/after."
    Tests = g_suite_brute_force_login_tests

    def rule(self, event):
        # Filter login events
        if event.get("type") != "login":
            return False
        # Pattern match this event to the recon actions
        return bool(event.get("name") == "login_failure")

    def title(self, event):
        return f"Brute force login suspected for user [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}]"
