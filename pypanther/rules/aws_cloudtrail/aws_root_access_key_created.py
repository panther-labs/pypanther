from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get

aws_cloud_trail_root_access_key_created_tests: list[RuleTest] = [
    RuleTest(
        name="Root Access Key Created",
        expected_result=True,
        log={
            "awsRegion": "us-east-1",
            "eventID": "1111",
            "eventName": "CreateAccessKey",
            "eventSource": "iam.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": None,
            "responseElements": {
                "accessKey": {"accessKeyId": "1111", "createDate": "Jan 01, 2019 0:00:00 PM", "status": "Active"},
            },
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "signin.amazonaws.com",
            "userIdentity": {
                "accessKeyId": "1111",
                "accountId": "123456789012",
                "arn": "arn:aws:iam::123456789012:root",
                "invokedBy": "signin.amazonaws.com",
                "principalId": "123456789012",
                "sessionContext": {"attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"}},
                "type": "Root",
            },
        },
    ),
    RuleTest(
        name="Root Created Access Key For User",
        expected_result=False,
        log={
            "awsRegion": "us-east-1",
            "eventID": "1111",
            "eventName": "CreateAccessKey",
            "eventSource": "iam.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {"userName": "example-user"},
            "responseElements": {
                "accessKey": {
                    "accessKeyId": "1111",
                    "createDate": "Jan 01, 2019 0:00:00 PM",
                    "status": "Active",
                    "userName": "example-user",
                },
            },
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "signin.amazonaws.com",
            "userIdentity": {
                "accessKeyId": "1111",
                "accountId": "123456789012",
                "arn": "arn:aws:iam::123456789012:root",
                "invokedBy": "signin.amazonaws.com",
                "principalId": "123456789012",
                "sessionContext": {"attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"}},
                "type": "Root",
            },
        },
    ),
]


@panther_managed
class AWSCloudTrailRootAccessKeyCreated(Rule):
    id = "AWS.CloudTrail.RootAccessKeyCreated-prototype"
    display_name = "Root Account Access Key Created"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Identity and Access Management", "Persistence:Account Manipulation"]
    reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    default_severity = Severity.CRITICAL
    default_description = "An access key was created for the Root account"
    default_runbook = "Verify that the root access key was created for legitimate reasons. If not, immediately revoke it and change the root login credentials. If it was created for legitimate reasons, monitor its use and ensure it is revoked when its need is gone.\n"
    default_reference = "https://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html"
    summary_attributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    tests = aws_cloud_trail_root_access_key_created_tests

    def rule(self, event):
        # Only check access key creation events
        if event.get("eventName") != "CreateAccessKey":
            return False
        # Only root can create root access keys
        if deep_get(event, "userIdentity", "type") != "Root":
            return False
        # Only alert if the root user is creating an access key for itself
        return event.get("requestParameters") is None

    def alert_context(self, event):
        return aws_rule_context(event)
