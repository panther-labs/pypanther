from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

g_suite_google_access_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Normal Login Event",
        ExpectedResult=False,
        Log={"id": {"applicationName": "login"}, "type": "login"},
    ),
    PantherRuleTest(
        Name="Resource Accessed by Google",
        ExpectedResult=True,
        Log={"id": {"applicationName": "access_transparency"}, "type": "GSUITE_RESOURCE"},
    ),
]


class GSuiteGoogleAccess(PantherRule):
    RuleID = "GSuite.GoogleAccess-prototype"
    DisplayName = "Google Accessed a GSuite Resource"
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite"]
    Severity = PantherSeverity.Low
    Description = "Google accessed one of your GSuite resources directly, most likely in response to a support incident.\n"
    Reference = "https://support.google.com/a/answer/9230474?hl=en"
    Runbook = "Your GSuite Super Admin can visit the Access Transparency report in the GSuite Admin Dashboard to see more details about the access.\n"
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_google_access_tests

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "access_transparency":
            return False
        return bool(event.get("type") == "GSUITE_RESOURCE")
