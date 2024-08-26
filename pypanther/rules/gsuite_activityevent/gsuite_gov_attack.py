from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

g_suite_government_backed_attack_tests: list[RuleTest] = [
    RuleTest(
        name="Normal Login Event",
        expected_result=False,
        log={
            "id": {"applicationName": "login"},
            "actor": {"email": "homer.simpson@example.com"},
            "type": "login",
            "name": "login_success",
            "parameters": {"is_suspicious": None, "login_challenge_method": ["none"]},
        },
    ),
    RuleTest(
        name="Government Backed Attack Warning",
        expected_result=True,
        log={
            "id": {"applicationName": "login"},
            "actor": {"email": "homer.simpson@example.com"},
            "type": "login",
            "name": "gov_attack_warning",
            "parameters": {"is_suspicious": None, "login_challenge_method": ["none"]},
        },
    ),
]


@panther_managed
class GSuiteGovernmentBackedAttack(Rule):
    id = "GSuite.GovernmentBackedAttack-prototype"
    display_name = "GSuite Government Backed Attack"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite"]
    default_severity = Severity.CRITICAL
    default_description = "GSuite reported that it detected a government backed attack against your account.\n"
    default_reference = "https://support.google.com/a/answer/9007870?hl=en"
    default_runbook = "Followup with GSuite support for more details.\n"
    summary_attributes = ["actor:email"]
    tests = g_suite_government_backed_attack_tests

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "login":
            return False
        return bool(event.get("name") == "gov_attack_warning")

    def title(self, event):
        return f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}] may have been targeted by a government attack"
