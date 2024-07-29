from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_duo_helpers import deserialize_administrator_log_event_description, duo_alert_context

duo_admin_user_mfa_bypass_enabled_tests: list[RuleTest] = [
    RuleTest(
        name="Account Active",
        expected_result=False,
        log={
            "action": "user_update",
            "description": '{"status": "Active"}',
            "isotimestamp": "2021-10-05 22:45:33",
            "object": "bart.simpson@simpsons.com",
            "timestamp": "2021-10-05 22:45:33",
            "username": "Homer Simpson",
        },
    ),
    RuleTest(
        name="Account Disabled",
        expected_result=False,
        log={
            "action": "user_update",
            "description": '{"status": "Disabled"}',
            "isotimestamp": "2021-10-05 22:45:33",
            "object": "bart.simpson@simpsons.com",
            "timestamp": "2021-10-05 22:45:33",
            "username": "Homer Simpson",
        },
    ),
    RuleTest(
        name="Bypass Enabled",
        expected_result=True,
        log={
            "action": "user_update",
            "description": '{"status": "Bypass"}',
            "isotimestamp": "2021-10-05 22:45:33",
            "object": "bart.simpson@simpsons.com",
            "timestamp": "2021-10-05 22:45:33",
            "username": "Homer Simpson",
        },
    ),
    RuleTest(
        name="Phones Update",
        expected_result=False,
        log={
            "action": "user_update",
            "description": '{"phones": ""}',
            "isotimestamp": "2021-07-02 19:06:40",
            "object": "homer.simpson@simpsons.com",
            "timestamp": "2021-07-02 19:06:40",
            "username": "Homer Simpson",
        },
    ),
]


@panther_managed
class DuoAdminUserMFABypassEnabled(Rule):
    default_description = "An Administrator enabled a user to authenticate without MFA."
    display_name = "Duo Admin User MFA Bypass Enabled"
    default_reference = "https://duo.com/docs/policy#authentication-policy"
    default_severity = Severity.MEDIUM
    log_types = [LogType.DUO_ADMINISTRATOR]
    id = "Duo.Admin.User.MFA.Bypass.Enabled-prototype"
    tests = duo_admin_user_mfa_bypass_enabled_tests

    def rule(self, event):
        if event.get("action") == "user_update":
            description = deserialize_administrator_log_event_description(event)
            if "status" in description:
                return description.get("status") == "Bypass"
        return False

    def title(self, event):
        return f"Duo: [{event.get('username', '<username_not_found>')}] updated account [{event.get('object', '<object_not_found>')}] to not require two-factor authentication."

    def alert_context(self, event):
        return duo_alert_context(event)
