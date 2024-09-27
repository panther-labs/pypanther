from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class ZoomSignInRequirementsChanged(Rule):
    default_description = "A Zoom User changed your organization's sign in requirements. "
    display_name = "Zoom Sign In Requirements Changed"
    default_runbook = (
        "Confirm this user acted with valid business intent and determine whether this activity was authorized."
    )
    default_reference = "https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0061263"
    default_severity = Severity.MEDIUM
    log_types = [LogType.ZOOM_OPERATION]
    id = "Zoom.Sign.In.Requirements.Changed-prototype"
    summary_attributes = ["operation_detail"]

    def rule(self, event):
        operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
        operation_flag_one = "Sign-In Password Requirement"
        operation_flag_two = "On to Off"
        return all(
            [
                event.get("action", "<NO_ACTION>") == "Update",
                event.get("category_type", "<NO_CATEGORY_TYPE>") == "Account",
                operation_flag_one in operation_detail,
                operation_flag_two in operation_detail,
            ],
        )

    def title(self, event):
        return f"Zoom User [{event.get('operator', '<NO_OPERATOR>')}] changed your organization's sign in requirements [{event.get('operation_detail', '<NO_OPS_DETAIL>')}]."

    tests = [
        RuleTest(
            name="Setting Change One",
            expected_result=True,
            log={
                "action": "Update",
                "category_type": "Account",
                "operation_detail": "Sign-In Password Requirement  - Include at least 1 letter: from On to Off - Include at least 1 number: from On to Off - Include both uppercase and lowercase characters: from On to Off",
                "operator": "example@example.io",
                "time": "2022-12-16 18:21:29",
            },
        ),
        RuleTest(
            name="Setting Change Two",
            expected_result=True,
            log={
                "action": "Update",
                "category_type": "Account",
                "operation_detail": "Sign-In Password Requirement  - Have at least specified length of characters: from 8 to 14 - Include at least 1 letter: from On to Off - Include at least 1 number: from On to Off - Include both uppercase and lowercase characters: from On to Off",
                "operator": "example@example.io",
                "time": "2022-12-16 18:21:23",
            },
        ),
        RuleTest(
            name="2FA disabled",
            expected_result=False,
            log={
                "action": "Update",
                "category_type": "Account",
                "operation_detail": "Security  - Sign in with Two-Factor Authentication: from On to Off",
                "operator": "example@example.io",
                "time": "2022-12-16 18:20:35",
            },
        ),
        RuleTest(
            name="Setting Change Off to On",
            expected_result=False,
            log={
                "action": "Update",
                "category_type": "Account",
                "operation_detail": "Sign-In Password Requirement  - Have at least specified length of characters: from 8 to 14 - Include at least 1 letter: from Off to On - Include at least 1 number: from Off to On - Include both uppercase and lowercase characters: from Off to On",
                "operator": "example@example.io",
                "time": "2022-12-16 18:21:23",
            },
        ),
    ]
