from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

one_login_auth_factor_removed_tests: list[RuleTest] = [
    RuleTest(
        name="User removed an auth factor",
        expected_result=True,
        log={
            "event_type_id": "172",
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_id": 123456,
            "user_name": "Bob Cat",
            "authentication_factor_description": "2FA Name",
        },
    ),
    RuleTest(
        name="User deactivated an otp deice",
        expected_result=True,
        log={
            "event_type_id": "24",
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_id": 123456,
            "user_name": "Bob Cat",
            "otp_device_name": "2FA Name",
        },
    ),
]


@panther_managed
class OneLoginAuthFactorRemoved(Rule):
    id = "OneLogin.AuthFactorRemoved-prototype"
    display_name = "OneLogin Authentication Factor Removed"
    log_types = [LogType.ONELOGIN_EVENTS]
    tags = ["OneLogin", "Identity & Access Management", "Defense Evasion:Modify Authentication Process"]
    reports = {"MITRE ATT&CK": ["TA0005:T1556"]}
    default_severity = Severity.LOW
    default_description = "A user removed an authentication factor or otp device.\n"
    default_reference = "https://onelogin.service-now.com/kb_view_customer.do?sysparm_article=KB0010426"
    default_runbook = "Investigate whether this was an intentional action and if other multifactor devices exist.\n"
    summary_attributes = [
        "account_id",
        "event_type_id",
        "user_name",
        "user_id",
        "authentication_factor_description",
        "otp_device_name",
    ]
    tests = one_login_auth_factor_removed_tests

    def rule(self, event):
        # verify this is a auth factor being removed
        # event id 24 is otp device deregistration
        # event id 172 is a user deleted an authentication factor
        return str(event.get("event_type_id")) == "24" or str(event.get("event_type_id")) == "172"

    def dedup(self, event):
        return event.get("user_name", "<UNKNOWN_USER>")

    def title(self, event):
        if str(event.get("event_type_id")) == "172":
            return f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] removed an authentication factor [{event.get('authentication_factor_description', '<UNKNOWN_AUTH_FACTOR>')}]"
        return f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] deactivated an otp device [{(event.get('otp_device_name', '<UNKNOWN_OTP_DEVICE>'),)}]"
