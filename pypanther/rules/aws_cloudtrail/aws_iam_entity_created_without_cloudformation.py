import re

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSCloudTrailIAMEntityCreatedWithoutCloudFormation(Rule):
    id = "AWS.CloudTrail.IAMEntityCreatedWithoutCloudFormation-prototype"
    display_name = "IAM Entity Created Without CloudFormation"
    enabled = False
    log_types = [LogType.AWS_CLOUDTRAIL]
    reports = {"MITRE ATT&CK": ["TA0003:T1136"]}
    tags = ["AWS", "Configuration Required", "Identity and Access Management", "Persistence:Create Account"]
    default_severity = Severity.MEDIUM
    default_description = "An IAM Entity (Group, Policy, Role, or User) was created manually. IAM entities should be created in code to ensure that permissions are tracked and managed correctly.\n"
    default_runbook = "Verify whether IAM entity needs to exist. If so, re-create it in an appropriate CloudFormation, Terraform, or other template. Delete the original manually created entity.\n"
    default_reference = "https://blog.awsfundamentals.com/aws-iam-roles-with-aws-cloudformation"
    summary_attributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
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
        if not aws_cloudtrail_success(event) or event.get("eventName") not in self.IAM_ENTITY_CREATION_EVENTS:
            return False
        # All IAM changes MUST go through CloudFormation
        if event.deep_get("userIdentity", "invokedBy") != "cloudformation.amazonaws.com":
            return True
        # Only approved IAM Roles can make IAM Changes
        for admin_role_pattern in self.IAM_ADMIN_ROLE_PATTERNS:
            # Check if the arn matches any role patterns, return False if there is a match
            if (
                len(
                    re.findall(
                        admin_role_pattern,
                        event.deep_get("userIdentity", "sessionContext", "sessionIssuer", "arn"),
                    ),
                )
                > 0
            ):
                return False
        return event.deep_get("userIdentity", "sessionContext", "sessionIssuer", "arn") not in self.IAM_ADMIN_ROLES

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="IAM Entity Created Automatically",
            expected_result=False,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "1111:tester",
                    "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "invokedBy": "cloudformation.amazonaws.com",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
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
        RuleTest(
            name="IAM Entity Created Manually With Approved Role",
            expected_result=True,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "1111:tester",
                    "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
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
        RuleTest(
            name="IAM Entity Created Manually With Approved Role Pattern",
            expected_result=False,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "1111:tester",
                    "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "invokedBy": "cloudformation.amazonaws.com",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
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
        RuleTest(
            name="IAM Entity Created Manually",
            expected_result=True,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "1111:tester",
                    "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
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
        RuleTest(
            name="Non IAM Entity Creation Event",
            expected_result=False,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "1111:tester",
                    "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
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
        RuleTest(
            name="Error Manually Creating IAM Entity",
            expected_result=False,
            log={
                "eventVersion": "1.05",
                "errorCode": "EntityAlreadyExists",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "1111:tester",
                    "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
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
