from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class OneLoginLogin(Rule):
    id = "OneLogin.Login-prototype"
    display_name = "Signal - OneLogin Login"
    create_alert = False
    log_types = [LogType.ONELOGIN_EVENTS]
    tags = ["OneLogin"]
    default_severity = Severity.INFO
    default_description = "A OneLogin user successfully logged in."
    default_reference = "https://resources.onelogin.com/OneLogin_RiskBasedAuthentication-WP-v5.pdf"

    def rule(self, event):
        if str(event.get("event_type_id")) == "5":
            return True
        return False

    def title(self, event):
        return f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] successfully logged in"

    tests = [
        RuleTest(
            name="Successful Login Event",
            expected_result=True,
            log={
                "event_type_id": "5",
                "actor_user_id": 123456,
                "actor_user_name": "Bob Cat",
                "user_id": 123456,
                "user_name": "Bob Cat",
            },
        ),
        RuleTest(
            name="Failed Login Event",
            expected_result=False,
            log={
                "event_type_id": "6",
                "actor_user_id": 123456,
                "actor_user_name": "Bob Cat",
                "user_id": 123456,
                "user_name": "Bob Cat",
            },
        ),
    ]
