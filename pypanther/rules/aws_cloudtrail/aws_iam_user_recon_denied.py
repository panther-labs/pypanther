from ipaddress import ip_address

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context, lookup_aws_account_name


@panther_managed
class AWSIAMUserReconAccessDenied(Rule):
    id = "AWS.IAMUser.ReconAccessDenied-prototype"
    display_name = "Detect Reconnaissance from IAM Users"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Discovery:Cloud Service Discovery"]
    reports = {"MITRE ATT&CK": ["TA0007:T1526"]}
    default_severity = Severity.INFO
    threshold = 15
    dedup_period_minutes = 10
    default_description = "An IAM user has a high volume of access denied API calls."
    default_runbook = "Analyze the IP they came from, and other actions taken before/after."
    default_reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html"
    summary_attributes = [
        "eventName",
        "userAgent",
        "sourceIpAddress",
        "recipientAccountId",
        "errorMessage",
        "p_any_aws_arns",
    ]
    # service/event patterns to monitor
    RECON_ACTIONS = {
        "dynamodb": ["List", "Describe", "Get"],
        "ec2": ["Describe", "Get"],
        "iam": ["List", "Get"],
        "s3": ["List", "Get"],
        "rds": ["Describe", "List"],
    }

    def rule(self, event):
        # Filter events
        if event.get("errorCode") != "AccessDenied":
            return False
        if event.deep_get("userIdentity", "type") != "IAMUser":
            return False
        # Console Activity can easily result in false positives as some pages contain a mix of
        # items that a user may or may not have access to.
        if event.get("userAgent").startswith("aws-internal/3"):
            return False
        # Validate the request came from outside of AWS
        try:
            ip_address(event.get("sourceIPAddress"))
        except ValueError:
            return False
        # Pattern match this event to the recon actions
        for event_source, event_patterns in self.RECON_ACTIONS.items():
            if event.get("eventSource", "").startswith(event_source) and any(
                event.get("eventName", "").startswith(event_pattern) for event_pattern in event_patterns
            ):
                return True
        return False

    def dedup(self, event):
        return event.deep_get("userIdentity", "arn")

    def title(self, event):
        user_type = event.deep_get("userIdentity", "type")
        if user_type == "IAMUser":
            user = event.deep_get("userIdentity", "userName")
        # root user
        elif user_type == "Root":
            user = user_type
        else:
            user = "<UNKNOWN_USER>"
        return f"Reconnaissance activity denied to user [{user}] in account [{lookup_aws_account_name(event.get('recipientAccountId'))}]"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Unauthorized API Call",
            expected_result=True,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "1111",
                    "arn": "arn:aws:iam::123456789012:user/tester",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "userName": "tester",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
                    },
                    "invokedBy": "signin.amazonaws.com",
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "GetRole",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "40.185.186.6",
                "errorCode": "AccessDenied",
                "errorMessage": "User: arn:aws:iam::123456789012:user/tester is not authorized to perform: iam:GetRole on resource: arn:aws:iam::123456789012:role/FooBar",
                "userAgent": "aws-sdk-go/1.32.7 (go1.14.6; linux; amd64) exec-env/AWS_Lambda_go1.x",
                "requestParameters": None,
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="Unauthorized API Call from Within AWS (FQDN)",
            expected_result=False,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "1111",
                    "arn": "arn:aws:iam::123456789012:user/tester",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "userName": "tester",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
                    },
                    "invokedBy": "signin.amazonaws.com",
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateServiceLinkedRole",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "sqs.amazonaws.com",
                "errorCode": "AccessDenied",
                "errorMessage": "User: arn:aws:iam::123456789012:user/tester is not authorized to perform: iam:Action on resource: arn:aws:iam::123456789012:resource",
                "userAgent": "sqs.amazonaws.com",
                "requestParameters": None,
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="Authorized API Call",
            expected_result=False,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "1111",
                    "arn": "arn:aws:iam::123456789012:user/tester",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "userName": "tester",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
                    },
                    "invokedBy": "signin.amazonaws.com",
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateServiceLinkedRole",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "signin.amazonaws.com",
                "requestParameters": None,
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="Unauthorized API Call - From AWS console",
            expected_result=False,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "1111",
                    "arn": "arn:aws:iam::123456789012:user/tester",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "userName": "tester",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
                    },
                    "invokedBy": "signin.amazonaws.com",
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "GetRole",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "40.185.186.6",
                "errorCode": "AccessDenied",
                "errorMessage": "User: arn:aws:iam::123456789012:user/tester is not authorized to perform: iam:GetRole on resource: arn:aws:iam::123456789012:role/FooBar",
                "userAgent": "aws-internal/3 aws-sdk-java/1.12.124 Linux/4.9.273-0.1.ac.226.84.332.metal1.x86_64 OpenJDK_64-Bit_Server_VM/25.312-b07 java/1.8.0_312 vendor/Oracle_Corporation cfg/retry-mode/standard",
                "requestParameters": None,
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
    ]
