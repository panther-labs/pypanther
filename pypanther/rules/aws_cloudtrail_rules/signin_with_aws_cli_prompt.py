from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

signinwith_awscl_iprompt_tests: list[RuleTest] = [
    RuleTest(
        name="Test-291327",
        expected_result=True,
        log={
            "eventName": "ListApplications",
            "eventSource": "sso.amazonaws.com",
            "eventTime": "...",
            "eventVersion": "1.08",
            "sourceIPAddress": "<Victim source IP>",
            "userAgent": "<Victim browser user agent>",
            "userIdentity": {
                "accountId": "<organization master account ID>",
                "principalId": "<internal victim user id>",
                "type": "Unknown",
                "userName": "<victim display name>",
            },
        },
    ),
]


@panther_managed
class SigninwithAWSCLIprompt(Rule):
    id = "Sign-in.with.AWS.CLI.prompt-prototype"
    display_name = "SIGNAL - Sign-in with AWS CLI prompt"
    create_alert = False
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.INFO
    tests = signinwith_awscl_iprompt_tests

    def rule(self, event):
        return event.get("eventSource") == "sso.amazonaws.com" and event.get("eventName") == "ListApplications"
