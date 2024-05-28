from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_duo_helpers import (
    deserialize_administrator_log_event_description,
    duo_alert_context,
)
from pypanther.log_types import LogType

duo_admin_user_mfa_bypass_enabled_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Account Active",
        ExpectedResult=False,
        Log={
            "action": "user_update",
            "description": '{"status": "Active"}',
            "isotimestamp": "2021-10-05 22:45:33",
            "object": "bart.simpson@simpsons.com",
            "timestamp": "2021-10-05 22:45:33",
            "username": "Homer Simpson",
        },
    ),
    PantherRuleTest(
        Name="Account Disabled",
        ExpectedResult=False,
        Log={
            "action": "user_update",
            "description": '{"status": "Disabled"}',
            "isotimestamp": "2021-10-05 22:45:33",
            "object": "bart.simpson@simpsons.com",
            "timestamp": "2021-10-05 22:45:33",
            "username": "Homer Simpson",
        },
    ),
    PantherRuleTest(
        Name="Bypass Enabled",
        ExpectedResult=True,
        Log={
            "action": "user_update",
            "description": '{"status": "Bypass"}',
            "isotimestamp": "2021-10-05 22:45:33",
            "object": "bart.simpson@simpsons.com",
            "timestamp": "2021-10-05 22:45:33",
            "username": "Homer Simpson",
        },
    ),
    PantherRuleTest(
        Name="Phones Update",
        ExpectedResult=False,
        Log={
            "action": "user_update",
            "description": '{"phones": ""}',
            "isotimestamp": "2021-07-02 19:06:40",
            "object": "homer.simpson@simpsons.com",
            "timestamp": "2021-07-02 19:06:40",
            "username": "Homer Simpson",
        },
    ),
]


class DuoAdminUserMFABypassEnabled(PantherRule):
    Description = "An Administrator enabled a user to authenticate without MFA."
    DisplayName = "Duo Admin User MFA Bypass Enabled"
    Reference = "https://duo.com/docs/policy#authentication-policy"
    Severity = PantherSeverity.Medium
    LogTypes = [LogType.Duo_Administrator]
    RuleID = "Duo.Admin.User.MFA.Bypass.Enabled-prototype"
    Tests = duo_admin_user_mfa_bypass_enabled_tests

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
