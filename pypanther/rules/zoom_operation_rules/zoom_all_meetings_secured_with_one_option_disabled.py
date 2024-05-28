from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

zoom_all_meetings_secured_with_one_option_disabled_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Turn off",
        ExpectedResult=True,
        Log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Security  - Require that all meetings are secured with one security option: from On to Off",
            "operator": "example@example.io",
            "time": "2022-12-16 18:15:38",
        },
    ),
    PantherRuleTest(
        Name="Turn on",
        ExpectedResult=False,
        Log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Security  - Require that all meetings are secured with one security option: from Off to On",
            "operator": "example@example.io",
            "time": "2022-12-16 18:15:38",
        },
    ),
    PantherRuleTest(
        Name="Non admin user update",
        ExpectedResult=False,
        Log={
            "action": "Update",
            "category_type": "User",
            "operation_detail": "Update User example@example.io  - Job Title: set to Contractor",
            "operator": "homer@example.io",
        },
    ),
]


class ZoomAllMeetingsSecuredWithOneOptionDisabled(PantherRule):
    Description = "A Zoom User turned off your organization's requirement that all meetings are secured with one security option."
    DisplayName = "Zoom All Meetings Secured With One Option Disabled"
    Runbook = "Confirm this user acted with valid business intent and determine whether this activity was authorized."
    Reference = "https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0059862"
    Severity = PantherSeverity.Medium
    LogTypes = [LogType.Zoom_Operation]
    RuleID = "Zoom.All.Meetings.Secured.With.One.Option.Disabled-prototype"
    Tests = zoom_all_meetings_secured_with_one_option_disabled_tests

    def rule(self, event):
        operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
        operation_flag = (
            "Require that all meetings are secured with one security option: from On to Off"
        )
        return (
            event.get("action", "<NO_ACTION>") == "Update"
            and event.get("category_type", "<NO_CATEGORY_TYPE>") == "Account"
            and (operation_flag in operation_detail)
        )

    def title(self, event):
        return f"Zoom User [{event.get('operator', '<NO_OPERATOR>')}] turned off your organization's requirement to secure all meetings with one security option."
