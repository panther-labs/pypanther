import re
from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.helpers.panther_default import aws_cloudtrail_success
from pypanther.log_types import LogType

aws_cloud_trail_iam_entity_created_without_cloud_formation_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="IAM Entity Created Automatically",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "invokedBy": "cloudformation.amazonaws.com",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-01-01T00:00:00Z",
                    },
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "1111",
                        "arn": "arn:aws:iam::123456789012:role/IdentityCFNServiceRole",
                        "accountId": "123456789012",
                        "userName": "tester",
                    },
                },
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.amazonaws.com",
            "requestParameters": {"userName": "user", "path": "/"},
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    PantherRuleTest(
        Name="IAM Entity Created Manually With Approved Role",
        ExpectedResult=True,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-01-01T00:00:00Z",
                    },
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "1111",
                        "arn": "arn:aws:iam::123456789012:role/IdentityCFNServiceRole",
                        "accountId": "123456789012",
                        "userName": "tester",
                    },
                },
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.amazonaws.com",
            "requestParameters": {"userName": "user", "path": "/"},
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    PantherRuleTest(
        Name="IAM Entity Created Manually With Approved Role Pattern",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "invokedBy": "cloudformation.amazonaws.com",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-01-01T00:00:00Z",
                    },
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "1111",
                        "arn": "arn:aws:iam::210987654321:role/IdentityCFNServiceRole",
                        "accountId": "123456789012",
                        "userName": "tester",
                    },
                },
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.amazonaws.com",
            "requestParameters": {"userName": "user", "path": "/"},
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    PantherRuleTest(
        Name="IAM Entity Created Manually",
        ExpectedResult=True,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-01-01T00:00:00Z",
                    },
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "1111",
                        "arn": "arn:aws:iam::123456789012:role/OtherRole",
                        "accountId": "123456789012",
                        "userName": "tester",
                    },
                },
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.amazonaws.com",
            "requestParameters": {"userName": "user", "path": "/"},
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    PantherRuleTest(
        Name="Non IAM Entity Creation Event",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-01-01T00:00:00Z",
                    },
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "1111",
                        "arn": "arn:aws:iam::123456789012:role/OtherRole",
                        "accountId": "123456789012",
                        "userName": "tester",
                    },
                },
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "NotCreateUser",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.amazonaws.com",
            "requestParameters": {"userName": "user", "path": "/"},
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    PantherRuleTest(
        Name="Error Manually Creating IAM Entity",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.05",
            "errorCode": "EntityAlreadyExists",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-01-01T00:00:00Z",
                    },
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "1111",
                        "arn": "arn:aws:iam::123456789012:role/OtherRole",
                        "accountId": "123456789012",
                        "userName": "tester",
                    },
                },
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.amazonaws.com",
            "requestParameters": {"userName": "user", "path": "/"},
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
]


class AWSCloudTrailIAMEntityCreatedWithoutCloudFormation(PantherRule):
    RuleID = "AWS.CloudTrail.IAMEntityCreatedWithoutCloudFormation-prototype"
    DisplayName = "IAM Entity Created Without CloudFormation"
    Enabled = False
    LogTypes = [LogType.AWS_CloudTrail]
    Reports = {"MITRE ATT&CK": ["TA0003:T1136"]}
    Tags = [
        "AWS",
        "Configuration Required",
        "Identity and Access Management",
        "Persistence:Create Account",
    ]
    Severity = PantherSeverity.Medium
    Description = "An IAM Entity (Group, Policy, Role, or User) was created manually. IAM entities should be created in code to ensure that permissions are tracked and managed correctly.\n"
    Runbook = "Verify whether IAM entity needs to exist. If so, re-create it in an appropriate CloudFormation, Terraform, or other template. Delete the original manually created entity.\n"
    Reference = "https://blog.awsfundamentals.com/aws-iam-roles-with-aws-cloudformation"
    SummaryAttributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    Tests = aws_cloud_trail_iam_entity_created_without_cloud_formation_tests
    # The role dedicated for IAM administration
    IAM_ADMIN_ROLES = {"arn:aws:iam::123456789012:role/IdentityCFNServiceRole"}
    # The role patterns dedicated for IAM Service Roles
    IAM_ADMIN_ROLE_PATTERNS = {"arn:aws:iam::[0-9]+:role/IdentityCFNServiceRole"}
    # API calls that are indicative of IAM entity creation
    IAM_ENTITY_CREATION_EVENTS = {
        "BatchCreateUser",
        "CreateGroup",
        "CreateInstanceProfile",
        "CreatePolicy",
        "CreatePolicyVersion",
        "CreateRole",
        "CreateServiceLinkedRole",
        "CreateUser",
    }

    def rule(self, event):
        # Check if this event is in scope
        if (
            not aws_cloudtrail_success(event)
            or event.get("eventName") not in self.IAM_ENTITY_CREATION_EVENTS
        ):
            return False
        # All IAM changes MUST go through CloudFormation
        if deep_get(event, "userIdentity", "invokedBy") != "cloudformation.amazonaws.com":
            return True
        # Only approved IAM Roles can make IAM Changes
        for admin_role_pattern in self.IAM_ADMIN_ROLE_PATTERNS:
            # Check if the arn matches any role patterns, return False if there is a match
            if (
                len(
                    re.findall(
                        admin_role_pattern,
                        deep_get(event, "userIdentity", "sessionContext", "sessionIssuer", "arn"),
                    )
                )
                > 0
            ):
                return False
        return (
            deep_get(event, "userIdentity", "sessionContext", "sessionIssuer", "arn")
            not in self.IAM_ADMIN_ROLES
        )

    def alert_context(self, event):
        return aws_rule_context(event)
