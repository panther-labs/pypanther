import json
from fnmatch import fnmatch
from unittest.mock import MagicMock

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSCloudTrailSecurityConfigurationChange(Rule):
    id = "AWS.CloudTrail.SecurityConfigurationChange-prototype"
    display_name = "Account Security Configuration Changed"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Defense Evasion:Impair Defenses"]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    default_description = "An account wide security configuration was changed."
    default_runbook = "Verify that this change was planned. If not, revert the change and update the access control policies to ensure this doesn't happen again.\n"
    default_reference = (
        "https://docs.aws.amazon.com/prescriptive-guidance/latest/aws-startup-security-baseline/controls-acct.html"
    )
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    SECURITY_CONFIG_ACTIONS = {
        "DeleteAccountPublicAccessBlock",
        "DeleteDeliveryChannel",
        "DeleteDetector",
        "DeleteFlowLogs",
        "DeleteRule",
        "DeleteTrail",
        "DisableEbsEncryptionByDefault",
        "DisableRule",
        "StopConfigurationRecorder",
        "StopLogging",
    }
    # Add expected events and users here to suppress alerts
    # {"userName": "ExampleUser", "eventName": "DeleteRule"},
    ALLOW_LIST = []

    def rule(self, event):
        if isinstance(self.ALLOW_LIST, MagicMock):
            self.ALLOW_LIST = json.loads(self.ALLOW_LIST())  # pylint: disable=not-callable
        if not aws_cloudtrail_success(event):
            return False
        for entry in self.ALLOW_LIST:
            if fnmatch(
                event.deep_get("userIdentity", "sessionContext", "sessionIssuer", "userName", default=""),
                entry["userName"],
            ):
                if fnmatch(event.get("eventName"), entry["eventName"]):
                    return False
        if event.get("eventName") == "UpdateDetector":
            return not event.deep_get("requestParameters", "enable", default=True)
        return event.get("eventName") in self.SECURITY_CONFIG_ACTIONS

    def title(self, event):
        user = event.deep_get("userIdentity", "userName") or event.deep_get(
            "userIdentity",
            "sessionContext",
            "sessionIssuer",
            "userName",
        )
        return f"Sensitive AWS API call {event.get('eventName')} made by {user}"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Security Configuration Changed",
            expected_result=True,
            log={
                "awsRegion": "us-west-2",
                "eventID": "1111",
                "eventName": "DeleteTrail",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsApiCall",
                "eventVersion": "1.05",
                "readOnly": False,
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": {"name": "example-trail"},
                "responseElements": None,
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla/2.0 (compatible; NEWT ActiveX; Win32)",
                "userIdentity": {
                    "accessKeyId": "1111",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
                    "invokedBy": "cloudformation.amazonaws.com",
                    "principalId": "1111",
                    "sessionContext": {
                        "attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/example-role",
                            "principalId": "1111",
                            "type": "Role",
                            "userName": "example-role",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Security Configuration Not Changed",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "eventID": "1111",
                "eventName": "DescribeTrail",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsApiCall",
                "eventVersion": "1.05",
                "readOnly": False,
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": {"name": "example-trail"},
                "responseElements": None,
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla/2.0 (compatible; NEWT ActiveX; Win32)",
                "userIdentity": {
                    "accessKeyId": "1111",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
                    "invokedBy": "cloudformation.amazonaws.com",
                    "principalId": "1111",
                    "sessionContext": {
                        "attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/example-role",
                            "principalId": "1111",
                            "type": "Role",
                            "userName": "example-role",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Non Security Configuration Change",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "eventID": "1111",
                "eventName": "PutPolicy",
                "eventSource": "iam.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsApiCall",
                "eventVersion": "1.05",
                "readOnly": False,
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": {"name": "example-trail"},
                "responseElements": None,
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla/2.0 (compatible; NEWT ActiveX; Win32)",
                "userIdentity": {
                    "accessKeyId": "1111",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
                    "invokedBy": "cloudformation.amazonaws.com",
                    "principalId": "1111",
                    "sessionContext": {
                        "attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/example-role",
                            "principalId": "1111",
                            "type": "Role",
                            "userName": "example-role",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Security Configuration Not Changed - Error",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "errorCode": "ConflictException",
                "eventID": "1111",
                "eventName": "DeleteTrail",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsApiCall",
                "eventVersion": "1.05",
                "readOnly": False,
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": {"name": "example-trail"},
                "responseElements": None,
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla/2.0 (compatible; NEWT ActiveX; Win32)",
                "userIdentity": {
                    "accessKeyId": "1111",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
                    "invokedBy": "cloudformation.amazonaws.com",
                    "principalId": "1111",
                    "sessionContext": {
                        "attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/example-role",
                            "principalId": "1111",
                            "type": "Role",
                            "userName": "example-role",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Security Configuration Changed - Allowlisted User",
            expected_result=False,
            mocks=[
                RuleMock(
                    object_name="ALLOW_LIST",
                    return_value='[{"userName": "ExampleUser", "eventName": "DeleteRule"}]',
                ),
            ],
            log={
                "awsRegion": "us-west-2",
                "eventID": "1111",
                "eventName": "DeleteRule",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsApiCall",
                "eventVersion": "1.05",
                "readOnly": False,
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": {"name": "example-trail"},
                "responseElements": None,
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla/2.0 (compatible; NEWT ActiveX; Win32)",
                "userIdentity": {
                    "accessKeyId": "1111",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
                    "invokedBy": "cloudformation.amazonaws.com",
                    "principalId": "1111",
                    "sessionContext": {
                        "attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/example-role",
                            "principalId": "1111",
                            "type": "Role",
                            "userName": "ExampleUser",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
    ]
