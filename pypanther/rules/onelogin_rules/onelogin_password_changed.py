from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

one_login_password_changed_tests: list[RuleTest] = [
    RuleTest(
        name="User changed their password",
        expected_result=True,
        log={
            "event_type_id": "11",
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
    RuleTest(
        name="User changed another's password",
        expected_result=True,
        log={
            "event_type_id": "11",
            "actor_user_id": 654321,
            "actor_user_name": "Mountain Lion",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
    RuleTest(
        name="Admin user changed another's password",
        expected_result=False,
        log={
            "event_type_id": "211",
            "actor_user_id": 654321,
            "actor_user_name": "Mountain Lion",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
]


@panther_managed
class OneLoginPasswordChanged(Rule):
    id = "OneLogin.PasswordChanged-prototype"
    display_name = "OneLogin User Password Changed"
    log_types = [LogType.ONELOGIN_EVENTS]
    tags = ["OneLogin", "Identity & Access Management"]
    default_severity = Severity.INFO
    default_description = "A user password was updated.\n"
    default_reference = "https://onelogin.service-now.com/kb_view_customer.do?sysparm_article=KB0010510"
    default_runbook = "Investigate whether this was an authorized action.\n"
    summary_attributes = ["account_id", "user_name", "user_id"]
    tests = one_login_password_changed_tests

    def rule(self, event):
        # check that this is a password change event;
        # event id 11 is actor_user changed password for user
        # Normally, admin's may change a user's password (event id 211)
        return str(event.get("event_type_id")) == "11"

    def title(self, event):
        return f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] password changed by user [{event.get('actor_user_name', '<UNKNOWN_USER>')}]"
