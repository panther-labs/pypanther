from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

one_login_password_access_tests: list[RuleTest] = [
    RuleTest(
        name="User accessed their own password",
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
        name="User accessed another user's password",
        expected_result=True,
        log={
            "event_type_id": "240",
            "actor_user_id": 654321,
            "actor_user_name": "Mountain Lion",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
]


@panther_managed
class OneLoginPasswordAccess(Rule):
    id = "OneLogin.PasswordAccess-prototype"
    display_name = "OneLogin Password Access"
    log_types = [LogType.ONELOGIN_EVENTS]
    tags = ["OneLogin", "Credential Access:Unsecured Credentials"]
    reports = {"MITRE ATT&CK": ["TA0006:T1552"]}
    default_severity = Severity.MEDIUM
    default_description = "User accessed another user's application password\n"
    default_reference = "https://onelogin.service-now.com/kb_view_customer.do?sysparm_article=KB0010598"
    default_runbook = "Investigate whether this was authorized access.\n"
    summary_attributes = ["account_id", "user_name", "user_id"]
    tests = one_login_password_access_tests

    def rule(self, event):
        # Filter events; event type 240 is actor_user revealed user's app password
        if str(event.get("event_type_id")) != "240" or not event.get("actor_user_id") or (not event.get("user_id")):
            return False
        # Determine if actor_user accessed another user's password
        return event.get("actor_user_id") != event.get("user_id")

    def dedup(self, event):
        return event.get("actor_user_name") + ":" + event.get("app_name", "<UNKNOWN_APP>")

    def title(self, event):
        return f"A user [{event.get('actor_user_name', '<UNKNOWN_USER>')}] accessed another user's [{event.get('user_name', '<UNKNOWN_USER>')}] [{event.get('app_name', '<UNKNOWN_APP>')}] password"
