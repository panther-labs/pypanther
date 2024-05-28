from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

zoom_sign_in_method_modified_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Google",
        ExpectedResult=True,
        Log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Sign-in Methods  - Allow users to sign in with Google: from Off to On",
            "operator": "example@example.io",
            "time": "2022-12-16 18:20:07",
        },
    ),
    PantherRuleTest(
        Name="Apple ID",
        ExpectedResult=True,
        Log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Sign-in Methods  - Allow users to sign in with Apple ID: from Off to On",
            "operator": "example@example.io",
            "time": "2022-12-16 18:19:57",
        },
    ),
    PantherRuleTest(
        Name="Automatic Sign Out Disabled",
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


class ZoomSignInMethodModified(PantherRule):
    Description = "A Zoom User modified your organizations sign in method."
    DisplayName = "Zoom Sign In Method Modified"
    Runbook = "Confirm this user acted with valid business intent and determine whether this activity was authorized."
    Reference = "https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0067602#:~:text=Go%20to%20the%20Zoom%20site,click%20Link%20and%20Sign%20In"
    Severity = PantherSeverity.Medium
    LogTypes = [LogType.Zoom_Operation]
    RuleID = "Zoom.Sign.In.Method.Modified-prototype"
    Tests = zoom_sign_in_method_modified_tests

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
            ]
        )

    def title(self, event):
        # string manipulation to grab service that allows sign-in from the operation detail
        # and clean it up a bit
        service_detail = ""
        operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
        operation_flag = "Sign-in Methods  - Allow users to sign in with "
        setting_flag = "from Off to On"
        if operation_detail.startswith(operation_flag) and operation_detail.endswith(setting_flag):
            service_detail = (
                event.get("operation_detail", "<NO_OPS_DETAIL>")
                .split("with")[1]
                .split(":")[0]
                .strip()
            )
        return f"Zoom User [{event.get('operator', '<NO_OPERATOR>')}] modified your organization's sign in methods to allow users to sign in with [{service_detail}]."
