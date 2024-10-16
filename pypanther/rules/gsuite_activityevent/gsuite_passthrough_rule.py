from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GSuiteRule(Rule):
    id = "GSuite.Rule-prototype"
    display_name = "GSuite Passthrough Rule Triggered"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite"]
    default_severity = Severity.INFO
    default_description = "A GSuite rule was triggered.\n"
    default_reference = "https://support.google.com/a/answer/9420866"
    default_runbook = "Investigate what triggered the rule.\n"
    summary_attributes = ["actor:email"]

    def rule(self, event):
        if event.deep_get("id", "applicationName") != "rules":
            return False
        if not event.deep_get("parameters", "triggered_actions"):
            return False
        return True

    def title(self, event):
        rule_severity = event.deep_get("parameters", "severity")
        if event.deep_get("parameters", "rule_name"):
            return "GSuite " + rule_severity + " Severity Rule Triggered: " + event.deep_get("parameters", "rule_name")
        return "GSuite " + rule_severity + " Severity Rule Triggered"

    def severity(self, event):
        return event.deep_get("parameters", "severity", default="INFO")

    tests = [
        RuleTest(
            name="Non Triggered Rule",
            expected_result=False,
            log={
                "id": {"applicationName": "rules"},
                "actor": {"email": "some.user@somedomain.com"},
                "parameters": {"severity": "HIGH", "triggered_actions": None},
            },
        ),
        RuleTest(
            name="High Severity Rule",
            expected_result=True,
            log={
                "id": {"applicationName": "rules"},
                "actor": {"email": "some.user@somedomain.com"},
                "parameters": {
                    "data_source": "DRIVE",
                    "severity": "HIGH",
                    "triggered_actions": [{"action_type": "DRIVE_UNFLAG_DOCUMENT"}],
                },
            },
        ),
        RuleTest(
            name="Medium Severity Rule",
            expected_result=True,
            log={
                "id": {"applicationName": "rules"},
                "actor": {"email": "some.user@somedomain.com"},
                "parameters": {
                    "data_source": "DRIVE",
                    "severity": "MEDIUM",
                    "triggered_actions": [{"action_type": "DRIVE_UNFLAG_DOCUMENT"}],
                },
            },
        ),
        RuleTest(
            name="Low Severity Rule",
            expected_result=True,
            log={
                "id": {"applicationName": "rules"},
                "actor": {"email": "some.user@somedomain.com"},
                "parameters": {"severity": "LOW", "triggered_actions": [{"action_type": "DRIVE_UNFLAG_DOCUMENT"}]},
            },
        ),
        RuleTest(
            name="High Severity Rule with Rule Name",
            expected_result=True,
            log={
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
