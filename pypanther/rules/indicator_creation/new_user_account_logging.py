from datetime import timedelta

from panther_detection_helpers.caching import put_string_set

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_oss_helpers import resolve_timestamp_string

standard_new_user_account_created_tests: list[RuleTest] = [
    RuleTest(
        name="User Creation Event - OneLogin",
        expected_result=True,
        mocks=[RuleMock(object_name="put_string_set", return_value="")],
        log={
            "event_type_id": 13,
            "actor_user_id": 123456,
            "user_id": 12345,
            "actor_user_name": "Bob Cat",
            "user_name": "Bob Cat",
            "p_event_time": "2021-06-27 00:08:28.792Z",
            "p_log_type": "OneLogin.Events",
            "p_row_id": "aaaaaaaabbbbbbbbbbbbccccccccc",
        },
    ),
    RuleTest(
        name="Standard Login Event - OneLogin",
        expected_result=False,
        log={
            "event_type_id": 5,
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_name": "Bob Cat",
            "user_id": 12345,
            "ipaddr": "192.168.1.1",
            "p_event_time": "2021-06-27 00:08:28.792Z",
            "p_log_type": "OneLogin.Events",
            "p_row_id": "aaaaaaaabbbbbbbbbbbbccccccccc",
        },
    ),
    RuleTest(
        name="User Account Created - CloudTrail",
        expected_result=True,
        mocks=[RuleMock(object_name="put_string_set", return_value="")],
        log={
            "eventName": "CreateUser",
            "responseElements": {"user": {"userName": "Bob Cat", "userId": "12345"}},
            "p_event_time": "2021-08-31 15:46:02.000000000",
            "p_log_type": "AWS.CloudTrail",
            "p_row_id": "aaaaaaaabbbbbbbbbbbbccccccccc",
        },
    ),
    RuleTest(
        name="Normal Console Login - CloudTrail",
        expected_result=False,
        log={
            "userIdentity": {"type": "IAMUser", "userName": "some_user"},
            "eventName": "ConsoleLogin",
            "responseElements": {"ConsoleLogin": "Success"},
            "p_event_time": "2021-06-04 09:59:53.650807",
            "p_row_id": "aaaaaaaabbbbbbbbbbbbccccccccc",
            "p_log_type": "AWS.CloudTrail",
        },
    ),
    RuleTest(
        name="User Creation Event - Zoom",
        expected_result=True,
        mocks=[RuleMock(object_name="put_string_set", return_value="")],
        log={
            "action": "Add",
            "category_type": "User",
            "operation_detail": "Add User homer@simpson.io  - User Type: Basic - Department: Foo",
            "operator": "abe@simpson.io",
            "p_log_type": "Zoom.Operation",
            "p_event_time": "2021-06-27 00:08:28.792Z",
        },
    ),
]


@panther_managed
class StandardNewUserAccountCreated(Rule):
    id = "Standard.NewUserAccountCreated-prototype"
    display_name = "New User Account Created"
    log_types = [LogType.ONELOGIN_EVENTS, LogType.AWS_CLOUDTRAIL, LogType.ZOOM_OPERATION]
    tags = ["DataModel", "Indicator Collection", "OneLogin", "Persistence:Create Account"]
    default_severity = Severity.INFO
    reports = {"MITRE ATT&CK": ["TA0003:T1136"]}
    default_description = "A new account was created"
    default_runbook = (
        "A new user account was created, ensure it was created through standard practice and is for a valid purpose."
    )
    default_reference = "https://attack.mitre.org/techniques/T1136/001/"
    summary_attributes = ["p_any_usernames"]
    tests = standard_new_user_account_created_tests
    # Days an account is considered new
    TTL = timedelta(days=3)

    def rule(self, event):
        if event.udm("event_type") != event_type.USER_ACCOUNT_CREATED:
            return False
        user_event_id = f"new_user_{event.get('p_row_id')}"
        new_user = event.udm("user") or "<UNKNOWN_USER>"
        new_account = event.udm("user_account_id") or "<UNKNOWN_ACCOUNT>"
        event_time = resolve_timestamp_string(event.get("p_event_time"))
        expiry_time = event_time + self.TTL
        if new_user:
            put_string_set(new_user + "-" + str(new_account), [user_event_id], expiry_time.strftime("%s"))
        return True

    def title(self, event):
        return f"A new user account was created - [{event.udm('user') or '<UNKNOWN_USER>'}]"
