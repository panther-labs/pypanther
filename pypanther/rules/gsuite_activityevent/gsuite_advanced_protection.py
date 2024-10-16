from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GSuiteAdvancedProtection(Rule):
    id = "GSuite.AdvancedProtection-prototype"
    display_name = "GSuite User Advanced Protection Change"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite", "Defense Evasion:Impair Defenses"]
    reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    default_severity = Severity.LOW
    default_description = "A user disabled advanced protection for themselves.\n"
    default_reference = "https://support.google.com/a/answer/9378686?hl=en&sjid=864417124752637253-EU"
    default_runbook = "Have the user re-enable Google Advanced Protection\n"
    summary_attributes = ["actor:email"]

    def rule(self, event):
        if event.deep_get("id", "applicationName") != "user_accounts":
            return False
        return bool(event.get("name") == "titanium_unenroll")

    def title(self, event):
        return (
            f"Advanced protection was disabled for user [{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}]"
        )

    tests = [
        RuleTest(
            name="Advanced Protection Enabled",
            expected_result=False,
            log={
                "id": {"applicationName": "user_accounts"},
                "actor": {"callerType": "USER", "email": "homer.simpson@example.com"},
                "type": "titanium_change",
                "name": "titanium_enroll",
            },
        ),
        RuleTest(
            name="Advanced Protection Disabled",
            expected_result=True,
            log={
                "id": {"applicationName": "user_accounts"},
                "actor": {"callerType": "USER", "email": "homer.simpson@example.com"},
                "type": "titanium_change",
                "name": "titanium_unenroll",
            },
        ),
    ]
