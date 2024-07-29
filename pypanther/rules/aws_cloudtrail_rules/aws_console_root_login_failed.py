from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.helpers.panther_default import lookup_aws_account_name

aws_console_root_login_failed_tests: list[RuleTest] = [
    RuleTest(
        name="Failed Root Login",
        expected_result=True,
        log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "Root",
                "principalId": "1111",
                "arn": "arn:aws:iam::123456789012:root",
                "accountId": "123456789012",
                "userName": "root",
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
                "MFAUsed": "No",
            },
            "eventID": "1",
            "eventType": "AwsConsoleSignIn",
            "recipientAccountId": "123456789012",
        },
    ),
    RuleTest(
        name="Successful Login",
        expected_result=False,
        log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "Root",
                "principalId": "1111",
                "arn": "arn:aws:iam::123456789012:root",
                "accountId": "123456789012",
                "userName": "root",
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla",
            "requestParameters": None,
            "responseElements": {"ConsoleLogin": "Success"},
            "additionalEventData": {
                "LoginTo": "https://console.aws.amazon.com/console/",
                "MobileVersion": "No",
                "MFAUsed": "No",
            },
            "eventID": "1",
            "eventType": "AwsConsoleSignIn",
            "recipientAccountId": "123456789012",
        },
    ),
    RuleTest(
        name="Non-Login Event",
        expected_result=False,
        log={
            "eventVersion": "1.06",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:user/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "1111",
                        "arn": "arn:aws:iam::123456789012:user/tester",
                        "accountId": "123456789012",
                        "userName": "tester",
                    },
                    "attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"},
                },
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "dynamodb.amazonaws.com",
            "eventName": "DescribeTable",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.amazonaws.com",
            "requestParameters": {"tableName": "table"},
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "readOnly": True,
            "resources": [{"accountId": "123456789012", "type": "AWS::DynamoDB::Table", "ARN": "arn::::table/table"}],
            "eventType": "AwsApiCall",
            "apiVersion": "2012-08-10",
            "managementEvent": True,
            "recipientAccountId": "123456789012",
        },
    ),
]


@panther_managed
class AWSConsoleRootLoginFailed(Rule):
    id = "AWS.Console.RootLoginFailed-prototype"
    display_name = "Failed Root Console Login"
    dedup_period_minutes = 15
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = [
        "AWS",
        "Identity & Access Management",
        "Authentication",
        "DemoThreatHunting",
        "Credential Access:Brute Force",
    ]
    threshold = 5
    reports = {"CIS": ["3.6"], "MITRE ATT&CK": ["TA0006:T1110"]}
    default_severity = Severity.HIGH
    default_description = "A Root console login failed."
    default_runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-console-login-failed"
    default_reference = "https://amzn.to/3aMSmTd"
    summary_attributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    tests = aws_console_root_login_failed_tests

    def rule(self, event):
        return (
            event.get("eventName") == "ConsoleLogin"
            and deep_get(event, "userIdentity", "type") == "Root"
            and (deep_get(event, "responseElements", "ConsoleLogin") == "Failure")
        )

    def title(self, event):
        return f"AWS root login failed from [{event.get('sourceIPAddress')}] in account [{lookup_aws_account_name(event.get('recipientAccountId'))}]"

    def alert_context(self, event):
        return aws_rule_context(event)
