from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class ZoomAllMeetingsSecuredWithOneOptionDisabled(Rule):
    default_description = (
        "A Zoom User turned off your organization's requirement that all meetings are secured with one security option."
    )
    display_name = "Zoom All Meetings Secured With One Option Disabled"
    default_runbook = (
        "Confirm this user acted with valid business intent and determine whether this activity was authorized."
    )
    default_reference = "https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0059862"
    default_severity = Severity.MEDIUM
    log_types = [LogType.ZOOM_OPERATION]
    id = "Zoom.All.Meetings.Secured.With.One.Option.Disabled-prototype"

    def rule(self, event):
        operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
        operation_flag = "Require that all meetings are secured with one security option: from On to Off"
        return (
            event.get("action", "<NO_ACTION>") == "Update"
            and event.get("category_type", "<NO_CATEGORY_TYPE>") == "Account"
            and (operation_flag in operation_detail)
        )

    def title(self, event):
        return f"Zoom User [{event.get('operator', '<NO_OPERATOR>')}] turned off your organization's requirement to secure all meetings with one security option."

    tests = [
        RuleTest(
            name="Turn off",
            expected_result=True,
            log={
                "action": "Update",
                "category_type": "Account",
                "operation_detail": "Security  - Require that all meetings are secured with one security option: from On to Off",
                "operator": "example@example.io",
                "time": "2022-12-16 18:15:38",
            },
        ),
        RuleTest(
            name="Turn on",
            expected_result=False,
            log={
                "action": "Update",
                "category_type": "Account",
                "operation_detail": "Security  - Require that all meetings are secured with one security option: from Off to On",
                "operator": "example@example.io",
                "time": "2022-12-16 18:15:38",
            },
        ),
        RuleTest(
            name="Non admin user update",
            expected_result=False,
            log={
                "action": "Update",
                "category_type": "User",
                "operation_detail": "Update User example@example.io  - Job Title: set to Contractor",
                "operator": "homer@example.io",
            },
        ),
    ]
