from fnmatch import fnmatch
from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.helpers.panther_default import aws_cloudtrail_success
from pypanther.log_types import LogType

aws_cloud_trail_security_configuration_change_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Security Configuration Changed",
        ExpectedResult=True,
        Log={
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
                    "attributes": {
                        "creationDate": "2019-01-01T00:00:00Z",
                        "mfaAuthenticated": "true",
                    },
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
    PantherRuleTest(
        Name="Security Configuration Not Changed",
        ExpectedResult=False,
        Log={
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
                    "attributes": {
                        "creationDate": "2019-01-01T00:00:00Z",
                        "mfaAuthenticated": "true",
                    },
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
    PantherRuleTest(
        Name="Non Security Configuration Change",
        ExpectedResult=False,
        Log={
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
                    "attributes": {
                        "creationDate": "2019-01-01T00:00:00Z",
                        "mfaAuthenticated": "true",
                    },
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
    PantherRuleTest(
        Name="Security Configuration Not Changed - Error",
        ExpectedResult=False,
        Log={
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
                    "attributes": {
                        "creationDate": "2019-01-01T00:00:00Z",
                        "mfaAuthenticated": "true",
                    },
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
    PantherRuleTest(
        Name="Security Configuration Changed - Allowlisted User",
        ExpectedResult=False,
        Log={
            "awsRegion": "us-west-2",
            "eventID": "1111",
            "eventName": "ExampleEvent",
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
                    "attributes": {
                        "creationDate": "2019-01-01T00:00:00Z",
                        "mfaAuthenticated": "true",
                    },
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


class AWSCloudTrailSecurityConfigurationChange(PantherRule):
    RuleID = "AWS.CloudTrail.SecurityConfigurationChange-prototype"
    DisplayName = "Account Security Configuration Changed"
    LogTypes = [LogType.AWS_CloudTrail]
    Tags = ["AWS", "Defense Evasion:Impair Defenses"]
    Severity = PantherSeverity.Medium
    Reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    Description = "An account wide security configuration was changed."
    Runbook = "Verify that this change was planned. If not, revert the change and update the access control policies to ensure this doesn't happen again.\n"
    Reference = "https://docs.aws.amazon.com/prescriptive-guidance/latest/aws-startup-security-baseline/controls-acct.html"
    SummaryAttributes = [
        "eventName",
        "userAgent",
        "sourceIpAddress",
        "recipientAccountId",
        "p_any_aws_arns",
    ]
    Tests = aws_cloud_trail_security_configuration_change_tests
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
    ALLOW_LIST = [{"userName": "ExampleUser", "eventName": "ExampleEvent"}]

    def rule(self, event):
        if not aws_cloudtrail_success(event):
            return False
        for entry in self.ALLOW_LIST:
            if fnmatch(
                deep_get(
                    event, "userIdentity", "sessionContext", "sessionIssuer", "userName", default=""
                ),
                entry["userName"],
            ):
                if fnmatch(event.get("eventName"), entry["eventName"]):
                    return False
        if event.get("eventName") == "UpdateDetector":
            return not deep_get(event, "requestParameters", "enable", default=True)
        return event.get("eventName") in self.SECURITY_CONFIG_ACTIONS

    def title(self, event):
        user = deep_get(event, "userIdentity", "userName") or deep_get(
            event, "userIdentity", "sessionContext", "sessionIssuer", "userName"
        )
        return f"Sensitive AWS API call {event.get('eventName')} made by {user}"

    def alert_context(self, event):
        return aws_rule_context(event)
