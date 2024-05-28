from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

zoom_two_factor_authentication_disabled_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="2FA Disabled",
        ExpectedResult=True,
        Log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Security  - Sign in with Two-Factor Authentication: from On to Off",
            "operator": "example@example.io",
            "time": "2022-12-16 18:20:35",
        },
    ),
    PantherRuleTest(
        Name="2FA Enabled",
        ExpectedResult=False,
        Log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Security  - Sign in with Two-Factor Authentication: from Off to On",
            "operator": "example@example.io",
            "time": "2022-12-16 18:20:35",
        },
    ),
    PantherRuleTest(
        Name="Sign In Apple ID ",
        ExpectedResult=False,
        Log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Sign-in Methods  - Allow users to sign in with Apple ID: from Off to On",
            "operator": "example@example.io",
            "time": "2022-12-16 18:19:57",
        },
    ),
]


class ZoomTwoFactorAuthenticationDisabled(PantherRule):
    Description = "A Zoom User disabled your organization's setting to sign in with Two-Factor Authentication."
    DisplayName = "Zoom Two Factor Authentication Disabled"
    Runbook = "Confirm this user acted with valid business intent and determine whether this activity was authorized."
    Reference = "https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0066054"
    Severity = PantherSeverity.Medium
    LogTypes = [LogType.Zoom_Operation]
    RuleID = "Zoom.Two.Factor.Authentication.Disabled-prototype"
    Tests = zoom_two_factor_authentication_disabled_tests

    def rule(self, event):
        operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
        operation_flag = "Security  - Sign in with Two-Factor Authentication: from On to Off"
        return all(
            [
                event.get("action", "<NO_ACTION>") == "Update",
                event.get("category_type", "<NO_CATEGORY_TYPE>") == "Account",
                operation_detail == operation_flag,
            ]
        )

    def title(self, event):
        return f"Zoom User [{event.get('operator', '<NO_OPERATOR>')}] disabled your organization's setting to sign in with Two-Factor Authentication."
