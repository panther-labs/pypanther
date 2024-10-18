from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSCloudTrailRootPasswordChanged(Rule):
    id = "AWS.CloudTrail.RootPasswordChanged-prototype"
    display_name = "Root Password Changed"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Identity and Access Management", "Persistence:Account Manipulation"]
    default_severity = Severity.HIGH
    reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    default_description = "Someone manually changed the Root console login password.\n"
    default_runbook = "Verify that the root password change was authorized. If not, AWS support should be contacted immediately as the root account cannot be recovered through normal means and grants complete access to the account.\n"
    default_reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_change-root.html"
    summary_attributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]

    def rule(self, event):
        # Only check password update changes
        if event.get("eventName") != "PasswordUpdated":
            return False
        # Only check root activity
        if event.deep_get("userIdentity", "type") != "Root":
            return False
        # Only alert if the login was a success
        return event.deep_get("responseElements", "PasswordUpdated") == "Success"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Root Password Changed",
            expected_result=True,
            log={
                "awsRegion": "us-east-1",
                "eventID": "1111",
                "eventName": "PasswordUpdated",
                "eventSource": "signin.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsConsoleSignIn",
                "eventVersion": "1.05",
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": None,
                "responseElements": {"PasswordUpdated": "Success"},
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36",
                "userIdentity": {
                    "accesKeyId": "1111",
                    "accessKeyId": "",
                    "accountId": "123456789012",
                    "arn": "arn:aws:iam::123456789012:root",
                    "principalId": "123456789012",
                    "type": "Root",
                },
            },
        ),
        RuleTest(
            name="Root Password Change Failed",
            expected_result=False,
            log={
                "awsRegion": "us-east-1",
                "eventID": "1111",
                "eventName": "PasswordUpdated",
                "eventSource": "signin.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsConsoleSignIn",
                "eventVersion": "1.05",
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": None,
                "responseElements": {"PasswordUpdated": "Failure"},
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36",
                "userIdentity": {
                    "accesKeyId": "1111",
                    "accessKeyId": "",
                    "accountId": "123456789012",
                    "arn": "arn:aws:iam::123456789012:root",
                    "principalId": "123456789012",
                    "type": "Root",
                },
            },
        ),
    ]
