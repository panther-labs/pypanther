from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_zoom_helpers import get_zoom_usergroup_context as get_context

zoom_passcode_disabled_tests: list[RuleTest] = [
    RuleTest(
        name="Meeting Passcode Disabled",
        expected_result=True,
        log={
            "time": "2021-11-17 00:37:24Z",
            "operator": "homer@panther.io",
            "category_type": "User Group",
            "action": "Update",
            "operation_detail": "Edit Group Springfield  - Personal Meeting ID (PMI) Passcode: from On to Off",
            "p_log_type": "Zoom.Operation",
        },
    ),
    RuleTest(
        name="Meeting Passcode Enabled",
        expected_result=False,
        log={
            "time": "2021-11-17 00:37:24Z",
            "operator": "homer@panther.io",
            "category_type": "User Group",
            "action": "Update",
            "operation_detail": "Edit Group Springfield  - Personal Meeting ID (PMI) Passcode: from Off to On",
            "p_log_type": "Zoom.Operation",
        },
    ),
    RuleTest(
        name="Add User Group",
        expected_result=False,
        log={
            "time": "2021-11-17 00:37:24Z",
            "operator": "homer@panther.io",
            "category_type": "User Group",
            "action": "Add",
            "operation_detail": "Add Group Engineers",
            "p_log_type": "Zoom.Operation",
        },
    ),
]


@panther_managed
class ZoomPasscodeDisabled(Rule):
    id = "Zoom.PasscodeDisabled-prototype"
    display_name = "Zoom Meeting Passcode Disabled"
    log_types = [LogType.ZOOM_OPERATION]
    tags = ["Zoom", "Collection:Video Capture"]
    default_severity = Severity.LOW
    default_description = "Meeting passcode requirement has been disabled from usergroup\n"
    reports = {"MITRE ATT&CK": ["TA0009:T1125"]}
    default_reference = "https://support.zoom.us/hc/en-us/articles/360033559832-Zoom-Meeting-and-Webinar-passcodes"
    default_runbook = (
        "Follow up with user or Zoom admin to ensure this meeting room's use case does not allow a passcode.\n"
    )
    summary_attributes = ["p_any_emails"]
    tests = zoom_passcode_disabled_tests

    def rule(self, event):
        if event.get("category_type") != "User Group":
            return False
        context = get_context(event)
        changed = "Passcode" in context.get("Change", "")
        disabled = context.get("DisabledSetting", False)
        return changed and disabled

    def title(self, event):
        context = get_context(event)
        return f"Group {context['GroupName']} passcode requirement disabled by {event.get('operator')}"
