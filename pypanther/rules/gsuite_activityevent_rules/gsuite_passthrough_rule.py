from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

g_suite_rule_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Non Triggered Rule",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "rules"},
            "actor": {"email": "some.user@somedomain.com"},
            "parameters": {"severity": "HIGH", "triggered_actions": None},
        },
    ),
    PantherRuleTest(
        Name="High Severity Rule",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "rules"},
            "actor": {"email": "some.user@somedomain.com"},
            "parameters": {
                "data_source": "DRIVE",
                "severity": "HIGH",
                "triggered_actions": [{"action_type": "DRIVE_UNFLAG_DOCUMENT"}],
            },
        },
    ),
    PantherRuleTest(
        Name="Medium Severity Rule",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "rules"},
            "actor": {"email": "some.user@somedomain.com"},
            "parameters": {
                "data_source": "DRIVE",
                "severity": "MEDIUM",
                "triggered_actions": [{"action_type": "DRIVE_UNFLAG_DOCUMENT"}],
            },
        },
    ),
    PantherRuleTest(
        Name="Low Severity Rule",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "rules"},
            "actor": {"email": "some.user@somedomain.com"},
            "parameters": {
                "severity": "LOW",
                "triggered_actions": [{"action_type": "DRIVE_UNFLAG_DOCUMENT"}],
            },
        },
    ),
    PantherRuleTest(
        Name="High Severity Rule with Rule Name",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "rules"},
            "actor": {"email": "some.user@somedomain.com"},
            "parameters": {
                "severity": "HIGH",
                "rule_name": "CEO Impersonation",
                "triggered_actions": [{"action_type": "MAIL_MARK_AS_PHISHING"}],
            },
        },
    ),
]


class GSuiteRule(PantherRule):
    RuleID = "GSuite.Rule-prototype"
    DisplayName = "GSuite Passthrough Rule Triggered"
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite"]
    Severity = PantherSeverity.Info
    Description = "A GSuite rule was triggered.\n"
    Reference = "https://support.google.com/a/answer/9420866"
    Runbook = "Investigate what triggered the rule.\n"
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_rule_tests

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "rules":
            return False
        if not deep_get(event, "parameters", "triggered_actions"):
            return False
        return True

    def title(self, event):
        rule_severity = deep_get(event, "parameters", "severity")
        if deep_get(event, "parameters", "rule_name"):
            return (
                "GSuite "
                + rule_severity
                + " Severity Rule Triggered: "
                + deep_get(event, "parameters", "rule_name")
            )
        return "GSuite " + rule_severity + " Severity Rule Triggered"

    def severity(self, event):
        return deep_get(event, "parameters", "severity", default="INFO")
