from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

one_login_high_risk_failed_login_tests: list[RuleTest] = [
    RuleTest(
        name="Normal Login Event",
        expected_result=False,
        log={
            "event_type_id": "6",
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
    RuleTest(
        name="Failed High Risk Login",
        expected_result=True,
        log={
            "event_type_id": "6",
            "risk_score": 55,
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
]


@panther_managed
class OneLoginHighRiskFailedLogin(Rule):
    id = "OneLogin.HighRiskFailedLogin-prototype"
    display_name = "OneLogin Failed High Risk Login"
    log_types = [LogType.ONELOGIN_EVENTS]
    tags = ["OneLogin"]
    default_severity = Severity.LOW
    default_description = "A OneLogin attempt with a high risk factor (>50) resulted in a failed authentication."
    default_reference = "https://resources.onelogin.com/OneLogin_RiskBasedAuthentication-WP-v5.pdf"
    default_runbook = "Investigate why this user login is tagged as high risk as well as whether this was caused by expected user activity."
    summary_attributes = ["account_id", "user_name", "user_id"]
    tests = one_login_high_risk_failed_login_tests

    def rule(self, event):
        # check risk associated with this event
        if event.get("risk_score", 0) > 50:
            # a failed authentication attempt with high risk
            return str(event.get("event_type_id")) == "6"
        return False

    def title(self, event):
        return f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] failed a high risk login attempt"
