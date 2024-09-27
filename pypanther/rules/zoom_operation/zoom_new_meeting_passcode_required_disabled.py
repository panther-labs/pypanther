from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class ZoomNewMeetingPasscodeRequiredDisabled(Rule):
    default_description = "A Zoom User turned off your organization's setting to require passcodes for new meetings."
    display_name = "Zoom New Meeting Passcode Required Disabled"
    default_runbook = (
        "Confirm this user acted with valid business intent and determine whether this activity was authorized."
    )
    default_reference = "https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0063160#:~:text=Since%20September%202022%2C%20Zoom%20requires,enforced%20for%20all%20free%20accounts"
    default_severity = Severity.MEDIUM
    log_types = [LogType.ZOOM_OPERATION]
    id = "Zoom.New.Meeting.Passcode.Required.Disabled-prototype"

    def rule(self, event):
        operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
        operation_flag = "Security  - Require a passcode when scheduling new meetings: from On to Off"
        return all(
            [
                event.get("action", "<NO_ACTION>") == "Update",
                event.get("category_type", "<NO_CATEGORY_TYPE>") == "Account",
                operation_flag == operation_detail,
            ],
        )

    def title(self, event):
        return f"Zoom User [{event.get('operator', '<NO_OPERATOR>')}] turned off your organization's setting to require passcodes for new meetings."

    tests = [
        RuleTest(
            name="Setting Turn Off",
            expected_result=True,
            log={
                "action": "Update",
                "category_type": "Account",
                "operation_detail": "Security  - Require a passcode when scheduling new meetings: from On to Off",
                "operator": "example@example.io",
                "time": "2022-12-16 18:22:17",
            },
        ),
        RuleTest(
            name="Setting Turn On",
            expected_result=False,
            log={
                "action": "Update",
                "category_type": "Account",
                "operation_detail": "Security  - Require a passcode when scheduling new meetings: from Off to On",
                "operator": "example@example.io",
                "time": "2022-12-16 18:22:17",
            },
        ),
        RuleTest(
            name="Automatic Sign Out Setting Disabled ",
            expected_result=False,
            log={
                "action": "Update",
                "category_type": "Account",
                "operation_detail": "Security  - Automatically sign users out after a specified time: from On to Off",
                "operator": "example@example.io",
                "time": "2022-12-16 18:20:42",
            },
        ),
    ]
