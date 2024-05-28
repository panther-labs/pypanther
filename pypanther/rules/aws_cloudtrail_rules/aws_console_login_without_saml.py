from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.helpers.panther_default import lookup_aws_account_name
from pypanther.log_types import LogType

aws_console_login_without_saml_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Login with SAML",
        ExpectedResult=False,
        Log={
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
    PantherRuleTest(
        Name="Normal Login",
        ExpectedResult=True,
        Log={
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


class AWSConsoleLoginWithoutSAML(PantherRule):
    RuleID = "AWS.Console.LoginWithoutSAML-prototype"
    DisplayName = "Logins Without SAML"
    Enabled = False
    LogTypes = [LogType.AWS_CloudTrail]
    Reports = {"MITRE ATT&CK": ["TA0001:T1078"]}
    Tags = [
        "AWS",
        "Configuration Required",
        "Identity & Access Management",
        "Authentication",
        "Initial Access:Valid Accounts",
    ]
    Severity = PantherSeverity.High
    Description = "An AWS console login was made without SAML/SSO."
    Runbook = "Modify the AWS account configuration."
    Reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-saml.html"
    SummaryAttributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    Tests = aws_console_login_without_saml_tests

    def rule(self, event):
        additional_event_data = event.get("additionalEventData", {})
        return (
            event.get("eventName") == "ConsoleLogin"
            and deep_get(event, "userIdentity", "type") != "AssumedRole"
            and (not additional_event_data.get("SamlProviderArn"))
        )

    def title(self, event):
        return f"AWS logins without SAML in account [{lookup_aws_account_name(event.get('recipientAccountId'))}]"

    def alert_context(self, event):
        return aws_rule_context(event)
