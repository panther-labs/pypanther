from collections.abc import Mapping
from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.helpers.panther_default import aws_cloudtrail_success
from pypanther.log_types import LogType

aws_cloud_trail_snapshot_made_public_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Snapshot Made Publicly Accessible",
        ExpectedResult=True,
        Log={
            "awsRegion": "us-west-2",
            "eventID": "1111",
            "eventName": "ModifySnapshotAttribute",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "attributeType": "CREATE_VOLUME_PERMISSION",
                "createVolumePermission": {"add": {"items": [{"group": "all"}]}},
                "snapshotId": "snap-1111",
            },
            "responseElements": {"_return": True, "requestId": "1111"},
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
        Name="Snapshot Not Made Publicly Accessible",
        ExpectedResult=False,
        Log={
            "awsRegion": "us-west-2",
            "eventID": "1111",
            "eventName": "ModifySnapshotAttribute",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "attributeType": "CREATE_VOLUME_PERMISSION",
                "createVolumePermission": {"add": {"items": [{"group": "none"}]}},
                "snapshotId": "snap-1111",
            },
            "responseElements": {"_return": True, "requestId": "1111"},
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
        Name="Error Making Snapshot Publicly Accessible",
        ExpectedResult=False,
        Log={
            "awsRegion": "us-west-2",
            "errorCode": "ValidationError",
            "eventID": "1111",
            "eventName": "ModifySnapshotAttribute",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "attributeType": "CREATE_VOLUME_PERMISSION",
                "createVolumePermission": {"add": {"items": [{"group": "all"}]}},
                "snapshotId": "snap-1111",
            },
            "responseElements": {"_return": True, "requestId": "1111"},
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


class AWSCloudTrailSnapshotMadePublic(PantherRule):
    RuleID = "AWS.CloudTrail.SnapshotMadePublic-prototype"
    DisplayName = "AWS Snapshot Made Public"
    LogTypes = [LogType.AWS_CloudTrail]
    Tags = ["AWS", "Exfiltration:Transfer Data to Cloud Account"]
    Reports = {"MITRE ATT&CK": ["TA0010:T1537"]}
    Severity = PantherSeverity.Medium
    Description = "An AWS storage snapshot was made public."
    Runbook = "Adjust the snapshot configuration so that it is no longer public."
    Reference = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html"
    SummaryAttributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    Tests = aws_cloud_trail_snapshot_made_public_tests

    def rule(self, event):
        if not aws_cloudtrail_success(event):
            return False
        # EC2 Volume snapshot made public
        if event.get("eventName") == "ModifySnapshotAttribute":
            parameters = event.get("requestParameters", {})
            if parameters.get("attributeType") != "CREATE_VOLUME_PERMISSION":
                return False
            items = deep_get(parameters, "createVolumePermission", "add", "items", default=[])
            for item in items:
                if not isinstance(item, (Mapping, dict)):
                    continue
                if item.get("userId") or item.get("group") == "all":
                    return True
            return False
        return False

    def alert_context(self, event):
        return aws_rule_context(event)
