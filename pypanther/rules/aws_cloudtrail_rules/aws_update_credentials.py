from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.helpers.panther_default import aws_cloudtrail_success
from pypanther.log_types import LogType

awsiam_credentials_updated_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="User Password Was Changed",
        ExpectedResult=True,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AAAAIIIIIIU74NPJW5K76",
                "arn": "arn:aws:iam::123456789012:user/test_user",
                "accountId": "123456789012",
                "accessKeyId": "AAAAIIIIIIU74NPJW5K76",
                "userName": "test_user",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-12-31T01:50:17Z",
                    }
                },
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
    PantherRuleTest(
        Name="MFA Device Was Created",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AAAAIIIIIIU74NPJW5K76",
                "arn": "arn:aws:iam::123456789012:user/test_user",
                "accountId": "123456789012",
                "accessKeyId": "AAAAIIIIIIU74NPJW5K76",
                "userName": "test_user",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-12-31T01:50:17Z",
                    }
                },
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
    PantherRuleTest(
        Name="User Password Change Error",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.05",
            "errorCode": "PasswordPolicyViolation",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AAAAIIIIIIU74NPJW5K76",
                "arn": "arn:aws:iam::123456789012:user/test_user",
                "accountId": "123456789012",
                "accessKeyId": "AAAAIIIIIIU74NPJW5K76",
                "userName": "test_user",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-12-31T01:50:17Z",
                    }
                },
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


class AWSIAMCredentialsUpdated(PantherRule):
    RuleID = "AWS.IAM.CredentialsUpdated-prototype"
    DisplayName = "New IAM Credentials Updated"
    LogTypes = [LogType.AWS_CloudTrail]
    Reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    Tags = ["AWS", "Identity & Access Management", "Persistence:Account Manipulation"]
    Severity = PantherSeverity.Info
    Description = "A console password, access key, or user has been created."
    Runbook = "This rule is purely informational, there is no action needed."
    Reference = (
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/list_identityandaccessmanagement.html"
    )
    SummaryAttributes = [
        "eventName",
        "userAgent",
        "sourceIpAddress",
        "recipientAccountId",
        "p_any_aws_arns",
    ]
    Tests = awsiam_credentials_updated_tests
    UPDATE_EVENTS = {"ChangePassword", "CreateAccessKey", "CreateLoginProfile", "CreateUser"}

    def rule(self, event):
        return event.get("eventName") in self.UPDATE_EVENTS and aws_cloudtrail_success(event)

    def dedup(self, event):
        return deep_get(event, "userIdentity", "userName", default="<UNKNOWN_USER>")

    def title(self, event):
        return f"{deep_get(event, 'userIdentity', 'type')} [{deep_get(event, 'userIdentity', 'arn')}] has updated their IAM credentials"

    def alert_context(self, event):
        return aws_rule_context(event)
