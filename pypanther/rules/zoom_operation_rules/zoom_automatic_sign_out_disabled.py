from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

zoom_automatic_sign_out_disabled_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Automatic Signout Setting Disabled",
        ExpectedResult=True,
        Log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Security  - Automatically sign users out after a specified time: from On to Off",
            "operator": "example@example.io",
            "time": "2022-12-16 18:20:42",
        },
    ),
    PantherRuleTest(
        Name="Meeting Setting Disabled",
        ExpectedResult=False,
        Log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Security  - Require that all meetings are secured with one security option: from On to Off",
            "operator": "example@example.io",
            "time": "2022-12-16 18:15:38",
        },
    ),
]


class ZoomAutomaticSignOutDisabled(PantherRule):
    Description = "A Zoom User turned off your organization's setting to automatically sign users out after a specified period of time."
    DisplayName = "Zoom Automatic Sign Out Disabled"
    Reference = "https://support.zoom.us/hc/en-us/articles/115005756143-Changing-account-security-settings#:~:text=Users%20need%20to%20sign%20in,of%205%20to%20120%20minutes"
    Runbook = "Confirm this user acted with valid business intent and determine whether this activity was authorized."
    Severity = PantherSeverity.Medium
    LogTypes = [LogType.Zoom_Operation]
    RuleID = "Zoom.Automatic.Sign.Out.Disabled-prototype"
    Tests = zoom_automatic_sign_out_disabled_tests

    def rule(self, event):
        operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
        operation_flag = "Automatically sign users out after a specified time: from On to Off"
        return (
            event.get("action", "<NO_ACTION>") == "Update"
            and event.get("category_type", "<NO_CATEGORY_TYPE>") == "Account"
            and (operation_flag in operation_detail)
        )

    def title(self, event):
        return f"Zoom User [{event.get('operator', '<NO_OPERATOR>')}] turned off your organization's setting to automatically sign users out after a specified time."
