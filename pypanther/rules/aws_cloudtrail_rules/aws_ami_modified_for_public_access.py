from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.helpers.panther_default import aws_cloudtrail_success
from pypanther.log_types import LogType

aws_cloud_trail_ami_modified_for_public_access_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="AMI Made Public",
        ExpectedResult=True,
        Log={
            "awsRegion": "us-west-2",
            "eventID": "1111",
            "eventName": "ModifyImageAttribute",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "attributeType": "launchPermission",
                "imageId": "ami-1111",
                "launchPermission": {"add": {"items": [{"group": "all"}]}},
            },
            "responseElements": {"_return": True},
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla/2.0 (compatible; NEWT ActiveX; Win32)",
            "userIdentity": {
                "accessKeyId": "1111",
                "accountId": "123456789012",
                "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
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
        Name="AMI Not Made Public",
        ExpectedResult=False,
        Log={
            "awsRegion": "us-west-2",
            "eventID": "1111",
            "eventName": "ModifyImageAttribute",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "attributeType": "launchPermission",
                "imageId": "ami-1111",
                "launchPermission": {"add": {"items": [{"group": "not-all"}]}},
            },
            "responseElements": {"_return": True},
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla/2.0 (compatible; NEWT ActiveX; Win32)",
            "userIdentity": {
                "accessKeyId": "1111",
                "accountId": "123456789012",
                "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
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
        Name="AMI Launch Permissions Not Modified",
        ExpectedResult=False,
        Log={
            "awsRegion": "us-west-2",
            "eventID": "1111",
            "eventName": "ModifyImageAttribute",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "attributeType": "someThing",
                "imageId": "ami-1111",
                "someThing": {"add": {"items": [{"group": "all"}]}},
            },
            "responseElements": {"_return": True},
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla/2.0 (compatible; NEWT ActiveX; Win32)",
            "userIdentity": {
                "accessKeyId": "1111",
                "accountId": "123456789012",
                "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
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
        Name="AMI Added to User",
        ExpectedResult=False,
        Log={
            "awsRegion": "us-west-2",
            "eventID": "1111",
            "eventName": "ModifyImageAttribute",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "attributeType": "launchPermission",
                "imageId": "ami-1111",
                "launchPermission": {"add": {"items": [{"userId": "bob"}]}},
            },
            "responseElements": {"_return": True},
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla/2.0 (compatible; NEWT ActiveX; Win32)",
            "userIdentity": {
                "accessKeyId": "1111",
                "accountId": "123456789012",
                "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
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
        Name="Error Making AMI Public",
        ExpectedResult=False,
        Log={
            "awsRegion": "us-west-2",
            "errorCode": "UnauthorizedOperation",
            "eventID": "1111",
            "eventName": "ModifyImageAttribute",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "attributeType": "launchPermission",
                "imageId": "ami-1111",
                "launchPermission": {"add": {"items": [{"group": "all"}]}},
            },
            "responseElements": {"_return": True},
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla/2.0 (compatible; NEWT ActiveX; Win32)",
            "userIdentity": {
                "accessKeyId": "1111",
                "accountId": "123456789012",
                "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
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
]


class AWSCloudTrailAMIModifiedForPublicAccess(PantherRule):
    RuleID = "AWS.CloudTrail.AMIModifiedForPublicAccess-prototype"
    DisplayName = "Amazon Machine Image (AMI) Modified to Allow Public Access"
    LogTypes = [LogType.AWS_CloudTrail]
    Tags = ["AWS", "Exfiltration:Transfer Data to Cloud Account"]
    Severity = PantherSeverity.Medium
    Reports = {"MITRE ATT&CK": ["TA0010:T1537"]}
    Description = "An Amazon Machine Image (AMI) was modified to allow it to be launched by anyone. Any sensitive configuration or application data stored in the AMI's block devices is at risk.\n"
    Runbook = "Determine if the AMI is intended to be publicly accessible. If not, first modify the AMI to not be publicly accessible then change any sensitive data stored in the block devices associated to the AMI (as they may be compromised).\n"
    Reference = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-intro.html"
    SummaryAttributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    Tests = aws_cloud_trail_ami_modified_for_public_access_tests

    def rule(self, event):
        # Only check successful ModiyImageAttribute events
        if not aws_cloudtrail_success(event) or event.get("eventName") != "ModifyImageAttribute":
            return False
        added_perms = deep_get(
            event, "requestParameters", "launchPermission", "add", "items", default=[]
        )
        for item in added_perms:
            if item.get("group") == "all":
                return True
        return False

    def alert_context(self, event):
        return aws_rule_context(event)
