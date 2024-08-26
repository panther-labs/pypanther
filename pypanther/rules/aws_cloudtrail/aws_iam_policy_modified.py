from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context
from pypanther.helpers.panther_default import aws_cloudtrail_success

awsiam_policy_modified_tests: list[RuleTest] = [
    RuleTest(
        name="IAM Policy Change",
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
                        "arn": "arn:aws:iam::123456789012:role/tester",
                        "accountId": "123456789012",
                        "userName": "tester",
                    },
                },
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "DeleteGroupPolicy",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.amazonaws.com",
            "requestParameters": {"policyName": "policy", "groupName": "group"},
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    RuleTest(
        name="Not IAM Policy Change",
        expected_result=False,
        log={
            "eventVersion": "1.06",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:tester",
                "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "1111",
                        "arn": "arn:aws:iam::123456789012:role/tester",
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
            "resources": [
                {
                    "accountId": "123456789012",
                    "type": "AWS::DynamoDB::Table",
                    "ARN": "arn:aws:dynamodb:us-west-2:123456789012:table/table",
                },
            ],
            "eventType": "AwsApiCall",
            "apiVersion": "2012-08-10",
            "managementEvent": True,
            "recipientAccountId": "123456789012",
        },
    ),
    RuleTest(
        name="IAM Policy Change Error",
        expected_result=False,
        log={
            "eventVersion": "1.05",
            "errorCode": "NoSuchEntity",
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
                        "arn": "arn:aws:iam::123456789012:role/tester",
                        "accountId": "123456789012",
                        "userName": "tester",
                    },
                },
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "DeleteGroupPolicy",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.amazonaws.com",
            "requestParameters": {"policyName": "policy", "groupName": "group"},
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
]


@panther_managed
class AWSIAMPolicyModified(Rule):
    id = "AWS.IAM.PolicyModified-prototype"
    display_name = "IAM Policy Modified"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Identity & Access Management", "Privilege Escalation:Abuse Elevation Control Mechanism"]
    reports = {"CIS": ["3.4"], "MITRE ATT&CK": ["TA0004:T1548"]}
    default_severity = Severity.INFO
    dedup_period_minutes = 720
    default_description = "An IAM Policy was changed.\n"
    default_runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-iam-policy-modified"
    default_reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    tests = awsiam_policy_modified_tests
    # API calls that are indicative of IAM Policy changes
    # Put<Entity>Policy is for inline policies.
    # these can be moved into their own rule if inline policies are of a greater concern.
    POLICY_CHANGE_EVENTS = {
        "DeleteGroupPolicy",
        "DeleteRolePolicy",
        "DeleteUserPolicy",
        "PutGroupPolicy",
        "PutRolePolicy",
        "PutUserPolicy",
        "CreatePolicy",
        "DeletePolicy",
        "CreatePolicyVersion",
        "DeletePolicyVersion",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "AttachUserPolicy",
        "DetachUserPolicy",
        "AttachGroupPolicy",
        "DetachGroupPolicy",
    }

    def rule(self, event):
        return aws_cloudtrail_success(event) and event.get("eventName") in self.POLICY_CHANGE_EVENTS

    def dedup(self, event):
        return event.get("recipientAccountId")

    def alert_context(self, event):
        return aws_rule_context(event)
