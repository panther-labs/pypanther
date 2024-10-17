from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSUnsuccessfulMFAattempt(Rule):
    default_description = "Monitor application logs for suspicious events including repeated MFA failures that may indicate user's primary credentials have been compromised."
    display_name = "AWS Unsuccessful MFA attempt"
    enabled = False
    default_reference = "https://attack.mitre.org/techniques/T1621/"
    tags = ["Configuration Required"]
    reports = {"MITRE ATT&CK": ["TA0006:T1621"]}
    default_severity = Severity.HIGH
    dedup_period_minutes = 15
    log_types = [LogType.AWS_CLOUDTRAIL]
    id = "AWS.Unsuccessful.MFA.attempt-prototype"
    threshold = 2

    def rule(self, event):
        if event.get("eventSource") != "signin.amazonaws.com" and event.get("eventName") != "ConsoleLogin":
            return False
        mfa_used = event.deep_get("additionalEventData", "MFAUsed", default="")
        console_login = event.deep_get("responseElements", "ConsoleLogin", default="")
        if mfa_used == "Yes" and console_login == "Failure":
            return True
        return False

    def title(self, event):
        arn = event.deep_get("userIdenity", "arn", default="No ARN")
        username = event.deep_get("userIdentity", "userName", default="No Username")
        return f"Failed MFA login from [{arn}] [{username}]"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Successful Login w/ MFA",
            expected_result=False,
            log={
                "additionalEventData": {
                    "LoginTo": "https://console.aws.amazon.com/console/home?state=hashArgs%23&isauthcode=true",
                    "MFAIdentifier": "arn:aws:iam::111122223333:u2f/user/anaya/default-AAAAAAAABBBBBBBBCCCCCCCCDD",
                    "MFAUsed": "Yes",
                    "MobileVersion": "No",
                },
                "awsRegion": "us-east-1",
                "eventID": "fed06f42-cb12-4764-8c69-121063dc79b9",
                "eventName": "ConsoleLogin",
                "eventSource": "signin.amazonaws.com",
                "eventTime": "2022-11-10T16:24:34Z",
                "eventType": "AwsConsoleSignIn",
                "eventVersion": "1.05",
                "recipientAccountId": "111122223333",
                "requestParameters": None,
                "responseElements": {"ConsoleLogin": "Success"},
                "sourceIPAddress": "192.0.2.0",
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36",
                "userIdentity": {
                    "accountId": "111122223333",
                    "arn": "arn:aws:iam::111122223333:user/anaya",
                    "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                    "type": "IAMUser",
                    "userName": "anaya",
                },
            },
        ),
        RuleTest(
            name="Unsuccessful Login w/ MFA",
            expected_result=True,
            log={
                "additionalEventData": {
                    "LoginTo": "https://console.aws.amazon.com/console/home?state=hashArgs%23&isauthcode=true",
                    "MFAUsed": "Yes",
                    "MobileVersion": "No",
                },
                "awsRegion": "us-east-1",
                "errorMessage": "Failed authentication",
                "eventID": "d38ce1b3-4575-4cb8-a632-611b8243bfc3",
                "eventName": "ConsoleLogin",
                "eventSource": "signin.amazonaws.com",
                "eventTime": "2022-11-10T16:24:34Z",
                "eventType": "AwsConsoleSignIn",
                "eventVersion": "1.05",
                "recipientAccountId": "111122223333",
                "requestParameters": None,
                "responseElements": {"ConsoleLogin": "Failure"},
                "sourceIPAddress": "192.0.2.0",
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36",
                "userIdentity": {
                    "accessKeyId": "",
                    "accountId": "111122223333",
                    "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                    "type": "IAMUser",
                    "userName": "anaya",
                },
            },
        ),
    ]
