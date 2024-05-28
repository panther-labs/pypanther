from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_zoom_helpers import get_zoom_usergroup_context as get_context
from pypanther.log_types import LogType

zoom_passcode_disabled_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Meeting Passcode Disabled",
        ExpectedResult=True,
        Log={
            "time": "2021-11-17 00:37:24Z",
            "operator": "homer@panther.io",
            "category_type": "User Group",
            "action": "Update",
            "operation_detail": "Edit Group Springfield  - Personal Meeting ID (PMI) Passcode: from On to Off",
            "p_log_type": "Zoom.Operation",
        },
    ),
    PantherRuleTest(
        Name="Meeting Passcode Enabled",
        ExpectedResult=False,
        Log={
            "time": "2021-11-17 00:37:24Z",
            "operator": "homer@panther.io",
            "category_type": "User Group",
            "action": "Update",
            "operation_detail": "Edit Group Springfield  - Personal Meeting ID (PMI) Passcode: from Off to On",
            "p_log_type": "Zoom.Operation",
        },
    ),
    PantherRuleTest(
        Name="Add User Group",
        ExpectedResult=False,
        Log={
            "time": "2021-11-17 00:37:24Z",
            "operator": "homer@panther.io",
            "category_type": "User Group",
            "action": "Add",
            "operation_detail": "Add Group Engineers",
            "p_log_type": "Zoom.Operation",
        },
    ),
]


class ZoomPasscodeDisabled(PantherRule):
    RuleID = "Zoom.PasscodeDisabled-prototype"
    DisplayName = "Zoom Meeting Passcode Disabled"
    LogTypes = [LogType.Zoom_Operation]
    Tags = ["Zoom", "Collection:Video Capture"]
    Severity = PantherSeverity.Low
    Description = "Meeting passcode requirement has been disabled from usergroup\n"
    Reports = {"MITRE ATT&CK": ["TA0009:T1125"]}
    Reference = (
        "https://support.zoom.us/hc/en-us/articles/360033559832-Zoom-Meeting-and-Webinar-passcodes"
    )
    Runbook = "Follow up with user or Zoom admin to ensure this meeting room's use case does not allow a passcode.\n"
    SummaryAttributes = ["p_any_emails"]
    Tests = zoom_passcode_disabled_tests

    def rule(self, event):
        if event.get("category_type") != "User Group":
            return False
        context = get_context(event)
        changed = "Passcode" in context.get("Change", "")
        disabled = context.get("DisabledSetting", False)
        return changed and disabled

    def title(self, event):
        context = get_context(event)
        return (
            f"Group {context['GroupName']} passcode requirement disabled by {event.get('operator')}"
        )
