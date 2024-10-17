from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSCloudTrailIAMAnythingChanged(Rule):
    id = "AWS.CloudTrail.IAMAnythingChanged-prototype"
    display_name = "IAM Change"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Identity and Access Management"]
    default_severity = Severity.INFO
    dedup_period_minutes = 720
    default_description = "A change occurred in the IAM configuration. This could be a resource being created, deleted, or modified. This is a high level view of changes, helfpul to indicate how dynamic a certain IAM environment is.\n"
    default_runbook = "Ensure this was an approved IAM configuration change.\n"
    default_reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html"
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    IAM_CHANGE_ACTIONS = [
        "Add",
        "Attach",
        "Change",
        "Create",
        "Deactivate",
        "Delete",
        "Detach",
        "Enable",
        "Put",
        "Remove",
        "Set",
        "Update",
        "Upload",
    ]

    def rule(self, event):
        # Only check IAM events, as the next check is relatively computationally
        # expensive and can often be skipped
        if not aws_cloudtrail_success(event) or event.get("eventSource") != "iam.amazonaws.com":
            return False
        return any(event.get("eventName", "").startswith(action) for action in self.IAM_CHANGE_ACTIONS)

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="IAM Change",
            expected_result=True,
            log={
                "awsRegion": "us-east-1",
                "eventID": "1111",
                "eventName": "AttachRolePolicy",
                "eventSource": "iam.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsApiCall",
                "eventVersion": "1.05",
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": {
                    "policyArn": "arn:aws:iam::aws:policy/example-policy",
                    "roleName": "LambdaFunctionRole-1111",
                },
                "responseElements": None,
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "cloudformation.amazonaws.com",
                "userIdentity": {
                    "accesKeyId": "1111",
                    "accessKeyId": "1111",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
                    "invokedBy": "cloudformation.amazonaws.com",
                    "principalId": "1111:example-user",
                    "sessionContext": {
                        "attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/example-role",
                            "principalId": "1111",
                            "type": "Role",
                            "userName": "example-user",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="IAM Read Only Activity",
            expected_result=False,
            log={
                "awsRegion": "us-east-1",
                "eventID": "1111",
                "eventName": "DescribePolicy",
                "eventSource": "iam.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsApiCall",
                "eventVersion": "1.05",
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": {"roleName": "LambdaFunctionRole-1111"},
                "responseElements": None,
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "cloudformation.amazonaws.com",
                "userIdentity": {
                    "accesKeyId": "1111",
                    "accessKeyId": "1111",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
                    "invokedBy": "cloudformation.amazonaws.com",
                    "principalId": "1111:example-user",
                    "sessionContext": {
                        "attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/example-role",
                            "principalId": "1111",
                            "type": "Role",
                            "userName": "example-user",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Error Making IAM Change",
            expected_result=False,
            log={
                "awsRegion": "us-east-1",
                "errorCode": "NoSuchEntity",
                "eventID": "1111",
                "eventName": "AttachRolePolicy",
                "eventSource": "iam.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsApiCall",
                "eventVersion": "1.05",
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": {
                    "policyArn": "arn:aws:iam::aws:policy/example-policy",
                    "roleName": "LambdaFunctionRole-1111",
                },
                "responseElements": None,
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "cloudformation.amazonaws.com",
                "userIdentity": {
                    "accesKeyId": "1111",
                    "accessKeyId": "1111",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
                    "invokedBy": "cloudformation.amazonaws.com",
                    "principalId": "1111:example-user",
                    "sessionContext": {
                        "attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/example-role",
                            "principalId": "1111",
                            "type": "Role",
                            "userName": "example-user",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
    ]
