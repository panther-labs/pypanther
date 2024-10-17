from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context, lookup_aws_account_name


@panther_managed
class AWSConsoleLoginWithoutSAML(Rule):
    id = "AWS.Console.LoginWithoutSAML-prototype"
    display_name = "Logins Without SAML"
    enabled = False
    log_types = [LogType.AWS_CLOUDTRAIL]
    reports = {"MITRE ATT&CK": ["TA0001:T1078"]}
    tags = [
        "AWS",
        "Configuration Required",
        "Identity & Access Management",
        "Authentication",
        "Initial Access:Valid Accounts",
    ]
    default_severity = Severity.HIGH
    default_description = "An AWS console login was made without SAML/SSO."
    default_runbook = "Modify the AWS account configuration."
    default_reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-saml.html"
    summary_attributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]

    def rule(self, event):
        additional_event_data = event.get("additionalEventData", {})
        return (
            event.get("eventName") == "ConsoleLogin"
            and event.deep_get("userIdentity", "type") != "AssumedRole"
            and (not additional_event_data.get("SamlProviderArn"))
        )

    def title(self, event):
        return f"AWS logins without SAML in account [{lookup_aws_account_name(event.get('recipientAccountId'))}]"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Login with SAML",
            expected_result=False,
            log={
                "additionalEventData": {
                    "LoginTo": "https://console.aws.amazon.com/console/home",
                    "MobileVersion": "No",
                    "MFAUsed": "No",
                    "SamlProviderArn": "arn:aws:iam::123456789012:saml-provider/Okta",
                },
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "1111",
                    "arn": "arn:aws:iam::123456789012:assumed-role/okta/tester@domain.tld",
                    "accountId": "123456789012",
                    "userName": "tester",
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla",
                "requestParameters": None,
                "responseElements": {"ConsoleLogin": "Success"},
                "eventID": "1",
                "eventType": "AwsConsoleSignIn",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="Normal Login",
            expected_result=True,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "1111",
                    "arn": "arn:aws:iam::123456789012:user/tester",
                    "accountId": "123456789012",
                    "userName": "tester",
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla",
                "requestParameters": None,
                "responseElements": {"ConsoleLogin": "Failure"},
                "additionalEventData": {
                    "LoginTo": "https://console.aws.amazon.com/console/",
                    "MobileVersion": "No",
                    "MFAUsed": "Yes",
                },
                "eventID": "1",
                "eventType": "AwsConsoleSignIn",
                "recipientAccountId": "123456789012",
            },
        ),
    ]
