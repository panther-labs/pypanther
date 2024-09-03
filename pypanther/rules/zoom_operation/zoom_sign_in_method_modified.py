from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

zoom_sign_in_method_modified_tests: list[RuleTest] = [
    RuleTest(
        name="Google",
        expected_result=True,
        log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Sign-in Methods  - Allow users to sign in with Google: from Off to On",
            "operator": "example@example.io",
            "time": "2022-12-16 18:20:07",
        },
    ),
    RuleTest(
        name="Apple ID",
        expected_result=True,
        log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Sign-in Methods  - Allow users to sign in with Apple ID: from Off to On",
            "operator": "example@example.io",
            "time": "2022-12-16 18:19:57",
        },
    ),
    RuleTest(
        name="Automatic Sign Out Disabled",
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


@panther_managed
class ZoomSignInMethodModified(Rule):
    default_description = "A Zoom User modified your organizations sign in method."
    display_name = "Zoom Sign In Method Modified"
    default_runbook = (
        "Confirm this user acted with valid business intent and determine whether this activity was authorized."
    )
    default_reference = "https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0067602#:~:text=Go%20to%20the%20Zoom%20site,click%20Link%20and%20Sign%20In"
    default_severity = Severity.MEDIUM
    log_types = [LogType.ZOOM_OPERATION]
    id = "Zoom.Sign.In.Method.Modified-prototype"
    tests = zoom_sign_in_method_modified_tests

    def rule(self, event):
        operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
        operation_flag = "Sign-in Methods  - Allow users to sign in with "
        setting_flag = "from Off to On"
        return all(
            [
                event.get("action", "<NO_ACTION>") == "Update",
                event.get("category_type", "<NO_CATEGORY_TYPE>") == "Account",
                operation_detail.startswith(operation_flag),
                operation_detail.endswith(setting_flag),
            ],
        )

    def title(self, event):
        # string manipulation to grab service that allows sign-in from the operation detail
        # and clean it up a bit
        service_detail = ""
        operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
        operation_flag = "Sign-in Methods  - Allow users to sign in with "
        setting_flag = "from Off to On"
        if operation_detail.startswith(operation_flag) and operation_detail.endswith(setting_flag):
            service_detail = event.get("operation_detail", "<NO_OPS_DETAIL>").split("with")[1].split(":")[0].strip()
        return f"Zoom User [{event.get('operator', '<NO_OPERATOR>')}] modified your organization's sign in methods to allow users to sign in with [{service_detail}]."
