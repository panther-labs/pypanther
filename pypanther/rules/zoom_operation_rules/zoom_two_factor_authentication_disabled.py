from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

zoom_two_factor_authentication_disabled_tests: list[RuleTest] = [
    RuleTest(
        name="2FA Disabled",
        expected_result=True,
        log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Security  - Sign in with Two-Factor Authentication: from On to Off",
            "operator": "example@example.io",
            "time": "2022-12-16 18:20:35",
        },
    ),
    RuleTest(
        name="2FA Enabled",
        expected_result=False,
        log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Security  - Sign in with Two-Factor Authentication: from Off to On",
            "operator": "example@example.io",
            "time": "2022-12-16 18:20:35",
        },
    ),
    RuleTest(
        name="Sign In Apple ID ",
        expected_result=False,
        log={
            "action": "Update",
            "category_type": "Account",
            "operation_detail": "Sign-in Methods  - Allow users to sign in with Apple ID: from Off to On",
            "operator": "example@example.io",
            "time": "2022-12-16 18:19:57",
        },
    ),
]


@panther_managed
class ZoomTwoFactorAuthenticationDisabled(Rule):
    default_description = "A Zoom User disabled your organization's setting to sign in with Two-Factor Authentication."
    display_name = "Zoom Two Factor Authentication Disabled"
    default_runbook = (
        "Confirm this user acted with valid business intent and determine whether this activity was authorized."
    )
    default_reference = "https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0066054"
    default_severity = Severity.MEDIUM
    log_types = [LogType.ZOOM_OPERATION]
    id = "Zoom.Two.Factor.Authentication.Disabled-prototype"
    tests = zoom_two_factor_authentication_disabled_tests

    def rule(self, event):
        operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
        operation_flag = "Security  - Sign in with Two-Factor Authentication: from On to Off"
        return all(
            [
                event.get("action", "<NO_ACTION>") == "Update",
                event.get("category_type", "<NO_CATEGORY_TYPE>") == "Account",
                operation_detail == operation_flag,
            ],
        )

    def title(self, event):
        return f"Zoom User [{event.get('operator', '<NO_OPERATOR>')}] disabled your organization's setting to sign in with Two-Factor Authentication."
