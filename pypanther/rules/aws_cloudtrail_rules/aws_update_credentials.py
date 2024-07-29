from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.helpers.panther_default import aws_cloudtrail_success

awsiam_credentials_updated_tests: list[RuleTest] = [
    RuleTest(
        name="User Password Was Changed",
        expected_result=True,
        log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AAAAIIIIIIU74NPJW5K76",
                "arn": "arn:aws:iam::123456789012:user/test_user",
                "accountId": "123456789012",
                "accessKeyId": "AAAAIIIIIIU74NPJW5K76",
                "userName": "test_user",
                "sessionContext": {"attributes": {"mfaAuthenticated": "true", "creationDate": "2019-12-31T01:50:17Z"}},
                "invokedBy": "signin.amazonaws.com",
            },
            "eventTime": "2019-12-31T01:50:46Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "ChangePassword",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "64.25.27.224",
            "userAgent": "signin.amazonaws.com",
            "requestParameters": None,
            "responseElements": None,
            "requestID": "a431f05e-67e1-11ea-bc55-0242ac130003",
            "eventID": "a431f05e-67e1-11ea-bc55-0242ac130003",
            "readOnly": False,
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    RuleTest(
        name="MFA Device Was Created",
        expected_result=False,
        log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AAAAIIIIIIU74NPJW5K76",
                "arn": "arn:aws:iam::123456789012:user/test_user",
                "accountId": "123456789012",
                "accessKeyId": "AAAAIIIIIIU74NPJW5K76",
                "userName": "test_user",
                "sessionContext": {"attributes": {"mfaAuthenticated": "true", "creationDate": "2019-12-31T01:50:17Z"}},
                "invokedBy": "signin.amazonaws.com",
            },
            "eventTime": "2019-12-31T01:50:46Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateVirtualMFADevice",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "64.25.27.224",
            "userAgent": "signin.amazonaws.com",
            "requestParameters": None,
            "responseElements": None,
            "requestID": "a431f05e-67e1-11ea-bc55-0242ac130003",
            "eventID": "a431f05e-67e1-11ea-bc55-0242ac130003",
            "readOnly": False,
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    RuleTest(
        name="User Password Change Error",
        expected_result=False,
        log={
            "eventVersion": "1.05",
            "errorCode": "PasswordPolicyViolation",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AAAAIIIIIIU74NPJW5K76",
                "arn": "arn:aws:iam::123456789012:user/test_user",
                "accountId": "123456789012",
                "accessKeyId": "AAAAIIIIIIU74NPJW5K76",
                "userName": "test_user",
                "sessionContext": {"attributes": {"mfaAuthenticated": "true", "creationDate": "2019-12-31T01:50:17Z"}},
                "invokedBy": "signin.amazonaws.com",
            },
            "eventTime": "2019-12-31T01:50:46Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "ChangePassword",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "64.25.27.224",
            "userAgent": "signin.amazonaws.com",
            "requestParameters": None,
            "responseElements": None,
            "requestID": "a431f05e-67e1-11ea-bc55-0242ac130003",
            "eventID": "a431f05e-67e1-11ea-bc55-0242ac130003",
            "readOnly": False,
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
]


@panther_managed
class AWSIAMCredentialsUpdated(Rule):
    id = "AWS.IAM.CredentialsUpdated-prototype"
    display_name = "New IAM Credentials Updated"
    log_types = [LogType.AWS_CLOUDTRAIL]
    reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    tags = ["AWS", "Identity & Access Management", "Persistence:Account Manipulation"]
    default_severity = Severity.INFO
    default_description = "A console password, access key, or user has been created."
    default_runbook = "This rule is purely informational, there is no action needed."
    default_reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/list_identityandaccessmanagement.html"
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    tests = awsiam_credentials_updated_tests
    UPDATE_EVENTS = {"ChangePassword", "CreateAccessKey", "CreateLoginProfile", "CreateUser"}

    def rule(self, event):
        return event.get("eventName") in self.UPDATE_EVENTS and aws_cloudtrail_success(event)

    def dedup(self, event):
        return deep_get(event, "userIdentity", "userName", default="<UNKNOWN_USER>")

    def title(self, event):
        return f"{deep_get(event, 'userIdentity', 'type')} [{deep_get(event, 'userIdentity', 'arn')}] has updated their IAM credentials"

    def alert_context(self, event):
        return aws_rule_context(event)
