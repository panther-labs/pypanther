from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

one_login_user_assumption_tests: list[RuleTest] = [
    RuleTest(
        name="User assumed their own account",
        expected_result=False,
        log={
            "event_type_id": "240",
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
    RuleTest(
        name="User assumed another user's account",
        expected_result=True,
        log={
            "event_type_id": "3",
            "actor_user_id": 654321,
            "actor_user_name": "Mountain Lion",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
]


@panther_managed
class OneLoginUserAssumption(Rule):
    id = "OneLogin.UserAssumption-prototype"
    display_name = "OneLogin User Assumed Another User"
    log_types = [LogType.ONELOGIN_EVENTS]
    tags = ["OneLogin", "Lateral Movement:Use Alternate Authentication Material"]
    reports = {"MITRE ATT&CK": ["TA0008:T1550"]}
    default_severity = Severity.LOW
    default_description = "User assumed another user account"
    default_reference = "https://onelogin.service-now.com/kb_view_customer.do?sysparm_article=KB0010594#:~:text=Prerequisites,Actions%20and%20select%20Assume%20User."
    default_runbook = "Investigate whether this was authorized access.\n"
    summary_attributes = ["account_id", "user_name", "user_id"]
    tests = one_login_user_assumption_tests

    def rule(self, event):
        # check that this is a user assumption event; event id 3
        return str(event.get("event_type_id")) == "3" and event.get("actor_user_id", "UNKNOWN_USER") != event.get(
            "user_id",
            "UNKNOWN_USER",
        )

    def title(self, event):
        return f"A user [{event.get('actor_user_name', '<UNKNOWN_USER>')}] assumed another user [{event.get('user_name', '<UNKNOWN_USER>')}] account"
