from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GSuiteTwoStepVerification(Rule):
    id = "GSuite.TwoStepVerification-prototype"
    display_name = "GSuite User Two Step Verification Change"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite", "Defense Evasion:Modify Authentication Process"]
    reports = {"MITRE ATT&CK": ["TA0005:T1556"]}
    default_severity = Severity.LOW
    default_description = "A user disabled two step verification for themselves.\n"
    default_reference = (
        "https://support.google.com/mail/answer/185839?hl=en&co=GENIE.Platform%3DDesktop&sjid=864417124752637253-EU"
    )
    default_runbook = (
        "Depending on company policy, either suggest or require the user re-enable two step verification.\n"
    )
    summary_attributes = ["actor:email"]

    def rule(self, event):
        if event.deep_get("id", "applicationName") != "user_accounts":
            return False
        if event.get("type") == "2sv_change" and event.get("name") == "2sv_disable":
            return True
        return False

    def title(self, event):
        return f"Two step verification was disabled for user [{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}]"

    tests = [
        RuleTest(
            name="Two Step Verification Enabled",
            expected_result=False,
            log={
                "id": {"applicationName": "user_accounts"},
                "actor": {"callerType": "USER", "email": "some.user@somedomain.com"},
                "kind": "admin#reports#activity",
                "type": "2sv_change",
                "name": "2sv_enroll",
            },
        ),
        RuleTest(
            name="Two Step Verification Disabled",
            expected_result=True,
            log={
                "id": {"applicationName": "user_accounts"},
                "actor": {"callerType": "USER", "email": "some.user@somedomain.com"},
                "kind": "admin#reports#activity",
                "type": "2sv_change",
                "name": "2sv_disable",
            },
        ),
    ]
