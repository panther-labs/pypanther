from datetime import timedelta
from typing import List

from panther_detection_helpers.caching import put_string_set

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherRule, PantherRuleMock, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_oss_helpers import resolve_timestamp_string
from pypanther.log_types import LogType

standard_new_user_account_created_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="User Creation Event - OneLogin",
        ExpectedResult=True,
        Mocks=[PantherRuleMock(ObjectName="put_string_set", ReturnValue="")],
        Log={
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
    PantherRuleTest(
        Name="Standard Login Event - OneLogin",
        ExpectedResult=False,
        Log={
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
    PantherRuleTest(
        Name="User Account Created - CloudTrail",
        ExpectedResult=True,
        Mocks=[PantherRuleMock(ObjectName="put_string_set", ReturnValue="")],
        Log={
            "eventName": "CreateUser",
            "responseElements": {"user": {"userName": "Bob Cat", "userId": "12345"}},
            "p_event_time": "2021-08-31 15:46:02.000000000",
            "p_log_type": "AWS.CloudTrail",
            "p_row_id": "aaaaaaaabbbbbbbbbbbbccccccccc",
        },
    ),
    PantherRuleTest(
        Name="Normal Console Login - CloudTrail",
        ExpectedResult=False,
        Log={
            "userIdentity": {"type": "IAMUser", "userName": "some_user"},
            "eventName": "ConsoleLogin",
            "responseElements": {"ConsoleLogin": "Success"},
            "p_event_time": "2021-06-04 09:59:53.650807",
            "p_row_id": "aaaaaaaabbbbbbbbbbbbccccccccc",
            "p_log_type": "AWS.CloudTrail",
        },
    ),
    PantherRuleTest(
        Name="User Creation Event - Zoom",
        ExpectedResult=True,
        Log={
            "action": "Add",
            "category_type": "User",
            "operation_detail": "Add User homer@simpson.io  - User Type: Basic - Department: Foo",
            "operator": "abe@simpson.io",
            "p_log_type": "Zoom.Operation",
            "p_event_time": "2021-06-27 00:08:28.792Z",
        },
    ),
]


class StandardNewUserAccountCreated(PantherRule):
    RuleID = "Standard.NewUserAccountCreated-prototype"
    DisplayName = "New User Account Created"
    LogTypes = [LogType.OneLogin_Events, LogType.AWS_CloudTrail, LogType.Zoom_Operation]
    Tags = ["DataModel", "Indicator Collection", "OneLogin", "Persistence:Create Account"]
    Severity = PantherSeverity.Info
    Reports = {"MITRE ATT&CK": ["TA0003:T1136"]}
    Description = "A new account was created"
    Runbook = "A new user account was created, ensure it was created through standard practice and is for a valid purpose."
    Reference = "https://attack.mitre.org/techniques/T1136/001/"
    SummaryAttributes = ["p_any_usernames"]
    Tests = standard_new_user_account_created_tests
    # Days an account is considered new
    TTL = timedelta(days=3)

    def rule(self, event):
        if event.udm("event_type") != event_type.USER_ACCOUNT_CREATED:
            return False
        user_event_id = f"new_user_{event.get('p_row_id')}"
        new_user = event.udm("user")
        new_account = event.udm("user_account_id") or "<UNKNOWN_ACCOUNT>"
        event_time = resolve_timestamp_string(event.get("p_event_time"))
        expiry_time = event_time + self.TTL
        if new_user:
            put_string_set(
                new_user + "-" + str(new_account), [user_event_id], expiry_time.strftime("%s")
            )
        return True

    def title(self, event):
        return f"A new user account was created - [{event.udm('user') or '<UNKNOWN_USER>'}]"
