from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

zoom_automatic_sign_out_disabled_tests: list[RuleTest] = [
    RuleTest(
        name="Automatic Signout Setting Disabled",
        expected_result=True,
        log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Security  - Automatically sign users out after a specified time: from On to Off",
            "operator": "example@example.io",
            "time": "2022-12-16 18:20:42",
        },
    ),
    RuleTest(
        name="Meeting Setting Disabled",
        expected_result=False,
        log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Security  - Require that all meetings are secured with one security option: from On to Off",
            "operator": "example@example.io",
            "time": "2022-12-16 18:15:38",
        },
    ),
]


@panther_managed
class ZoomAutomaticSignOutDisabled(Rule):
    default_description = "A Zoom User turned off your organization's setting to automatically sign users out after a specified period of time."
    display_name = "Zoom Automatic Sign Out Disabled"
    default_reference = "https://support.zoom.us/hc/en-us/articles/115005756143-Changing-account-security-settings#:~:text=Users%20need%20to%20sign%20in,of%205%20to%20120%20minutes"
    default_runbook = (
        "Confirm this user acted with valid business intent and determine whether this activity was authorized."
    )
    default_severity = Severity.MEDIUM
    log_types = [LogType.ZOOM_OPERATION]
    id = "Zoom.Automatic.Sign.Out.Disabled-prototype"
    tests = zoom_automatic_sign_out_disabled_tests

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
