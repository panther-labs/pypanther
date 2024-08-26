from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

okta_ss_oto_aws_tests: list[RuleTest] = [
    RuleTest(
        name="AWS SSO via Okta",
        expected_result=True,
        log={
            "displayMessage": "User single sign on to app",
            "eventType": "user.authentication.sso",
            "legacyEventType": "app.auth.sso",
            "outcome": {"result": "SUCCESS"},
            "securityContext": {},
            "severity": "INFO",
            "target": [
                {
                    "alternateId": "AWS Production",
                    "detailEntry": {"signOnModeType": "SAML_2_0"},
                    "displayName": "AWS IAM Identity Center",
                    "id": "0oaua5ldoougycQAO696",
                    "type": "AppInstance",
                },
                {"alternateId": "aardvark", "displayName": "aardvark", "id": "0ua8aardvarkD697", "type": "AppUser"},
            ],
            "transaction": {"detail": {}, "id": "1a3852fc0d172ecdad0e2447e47fbc98", "type": "WEB"},
            "uuid": "35cae732-21bd-11ef-a011-dd05aa53a11a",
            "version": "0",
        },
    ),
    RuleTest(
        name="AWS SSO via Okta without app name",
        expected_result=False,
        log={
            "displayMessage": "User single sign on to app",
            "eventType": "user.authentication.sso",
            "legacyEventType": "app.auth.sso",
            "outcome": {"result": "SUCCESS"},
            "securityContext": {},
            "severity": "INFO",
            "target": [{"alternateId": "aardvark", "id": "0ua8aardvarkD697", "type": "AppUser"}],
            "transaction": {"detail": {}, "id": "1a3852fc0d172ecdad0e2447e47fbc98", "type": "WEB"},
            "uuid": "35cae732-21bd-11ef-a011-dd05aa53a11a",
            "version": "0",
        },
    ),
]


@panther_managed
class OktaSSOtoAWS(Rule):
    id = "Okta.SSO.to.AWS-prototype"
    display_name = "SIGNAL - Okta SSO to AWS"
    create_alert = False
    log_types = [LogType.OKTA_SYSTEM_LOG]
    default_severity = Severity.INFO
    tests = okta_ss_oto_aws_tests

    def rule(self, event):
        return all(
            [
                event.get("eventType") == "user.authentication.sso",
                event.deep_get("outcome", "result") == "SUCCESS",
                "AWS IAM Identity Center" in event.deep_walk("target", "displayName", default=[]),
            ],
        )
