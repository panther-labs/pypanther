from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

one_login_user_account_locked_tests: list[RuleTest] = [
    RuleTest(
        name="User account locked via api - first method.",
        expected_result=True,
        log={
            "event_type_id": "531",
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
    RuleTest(
        name="User account locked via api - second method.",
        expected_result=True,
        log={
            "event_type_id": "553",
            "actor_user_id": 654321,
            "actor_user_name": "Mountain Lion",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
    RuleTest(
        name="User account suspended via api.",
        expected_result=True,
        log={
            "event_type_id": "551",
            "actor_user_id": 654321,
            "actor_user_name": "Mountain Lion",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
    RuleTest(
        name="Normal User Activated Event",
        expected_result=False,
        log={
            "event_type_id": "11",
            "actor_user_id": 654321,
            "actor_user_name": "Mountain Lion",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
]


@panther_managed
class OneLoginUserAccountLocked(Rule):
    id = "OneLogin.UserAccountLocked-prototype"
    display_name = "OneLogin User Locked"
    log_types = [LogType.ONELOGIN_EVENTS]
    tags = ["OneLogin", "Credential Access:Brute Force"]
    reports = {"MITRE ATT&CK": ["TA0006:T1110"]}
    default_severity = Severity.LOW
    default_description = "User locked or suspended from their account.\n"
    default_reference = "https://onelogin.service-now.com/kb_view_customer.do?sysparm_article=KB0010420"
    default_runbook = "Investigate whether this was caused by expected action.\n"
    summary_attributes = ["account_id", "event_type_id", "user_name", "user_id"]
    tests = one_login_user_account_locked_tests

    def rule(self, event):
        # check for a user locked event
        # event 531 and 553 are user lock events via api
        # event 551 is user suspended via api
        return str(event.get("event_type_id")) in ["531", "553", "551"]

    def title(self, event):
        return f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] was locked or suspended via api call"
