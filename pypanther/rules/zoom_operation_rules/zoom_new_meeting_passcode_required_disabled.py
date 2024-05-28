from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

zoom_new_meeting_passcode_required_disabled_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Setting Turn Off",
        ExpectedResult=True,
        Log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Security  - Require a passcode when scheduling new meetings: from On to Off",
            "operator": "example@example.io",
            "time": "2022-12-16 18:22:17",
        },
    ),
    PantherRuleTest(
        Name="Setting Turn On",
        ExpectedResult=False,
        Log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Security  - Require a passcode when scheduling new meetings: from Off to On",
            "operator": "example@example.io",
            "time": "2022-12-16 18:22:17",
        },
    ),
    PantherRuleTest(
        Name="Automatic Sign Out Setting Disabled ",
        ExpectedResult=False,
        Log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Security  - Automatically sign users out after a specified time: from On to Off",
            "operator": "example@example.io",
            "time": "2022-12-16 18:20:42",
        },
    ),
]


class ZoomNewMeetingPasscodeRequiredDisabled(PantherRule):
    Description = (
        "A Zoom User turned off your organization's setting to require passcodes for new meetings."
    )
    DisplayName = "Zoom New Meeting Passcode Required Disabled"
    Runbook = "Confirm this user acted with valid business intent and determine whether this activity was authorized."
    Reference = "https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0063160#:~:text=Since%20September%202022%2C%20Zoom%20requires,enforced%20for%20all%20free%20accounts"
    Severity = PantherSeverity.Medium
    LogTypes = [LogType.Zoom_Operation]
    RuleID = "Zoom.New.Meeting.Passcode.Required.Disabled-prototype"
    Tests = zoom_new_meeting_passcode_required_disabled_tests

    def rule(self, event):
        operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
        operation_flag = (
            "Security  - Require a passcode when scheduling new meetings: from On to Off"
        )
        return all(
            [
                event.get("action", "<NO_ACTION>") == "Update",
                event.get("category_type", "<NO_CATEGORY_TYPE>") == "Account",
                operation_flag == operation_detail,
            ]
        )

    def title(self, event):
        return f"Zoom User [{event.get('operator', '<NO_OPERATOR>')}] turned off your organization's setting to require passcodes for new meetings."
