from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class AWSConsoleSignIn(Rule):
    id = "AWS.Console.Sign-In-prototype"
    display_name = "SIGNAL - AWS Console SSO Sign-In"
    create_alert = False
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.INFO

    def rule(self, event):
        return event.get("eventSource") == "sso.amazonaws.com" and event.get("eventName") == "Authenticate"

    tests = [
        RuleTest(
            name="Test-94439c",
            expected_result=True,
            log={
                "awsRegion": "us-east-1",
                "eventCategory": "Management",
                "eventID": "8cb05708-9764-4774-a048-59a4c8e1684d",
                "eventName": "Authenticate",
                "eventSource": "sso.amazonaws.com",
                "eventTime": "2024-06-03 15:23:22.000000000",
                "eventType": "AwsServiceEvent",
                "eventVersion": "1.08",
                "managementEvent": True,
            },
        ),
    ]
