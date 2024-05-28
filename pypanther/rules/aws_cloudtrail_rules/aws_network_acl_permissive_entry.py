from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.helpers.panther_default import aws_cloudtrail_success
from pypanther.log_types import LogType

aws_cloud_trail_network_acl_permissive_entry_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Overly Permissive Entry Added",
        ExpectedResult=True,
        Log={
            "awsRegion": "us-west-2",
            "eventID": "1111",
            "eventName": "CreateNetworkAclEntry",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "aclProtocol": "6",
                "cidrBlock": "0.0.0.0/0",
                "egress": False,
                "icmpTypeCode": {},
                "networkAclId": "acl-1111",
                "portRange": {"from": 700, "to": 702},
                "ruleAction": "allow",
                "ruleNumber": 12,
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
        Name="Not Overly Permissive Entry Added",
        ExpectedResult=False,
        Log={
            "awsRegion": "us-west-2",
            "eventID": "1111",
            "eventName": "CreateNetworkAclEntry",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "aclProtocol": "6",
                "cidrBlock": "111.111.111.111/32",
                "egress": False,
                "icmpTypeCode": {},
                "networkAclId": "acl-1111",
                "portRange": {"from": 700, "to": 702},
                "ruleAction": "allow",
                "ruleNumber": 12,
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
        Name="Error Adding Overly Permissive Entry",
        ExpectedResult=False,
        Log={
            "awsRegion": "us-west-2",
            "errorCode": "ValidationError",
            "eventID": "1111",
            "eventName": "CreateNetworkAclEntry",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "aclProtocol": "6",
                "cidrBlock": "0.0.0.0/0",
                "egress": False,
                "icmpTypeCode": {},
                "networkAclId": "acl-1111",
                "portRange": {"from": 700, "to": 702},
                "ruleAction": "allow",
                "ruleNumber": 12,
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


class AWSCloudTrailNetworkACLPermissiveEntry(PantherRule):
    RuleID = "AWS.CloudTrail.NetworkACLPermissiveEntry-prototype"
    DisplayName = "AWS Network ACL Overly Permissive Entry Created"
    LogTypes = [LogType.AWS_CloudTrail]
    Tags = ["AWS", "Persistence:Account Manipulation"]
    Severity = PantherSeverity.Medium
    Reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    Description = "A Network ACL entry that allows access from anywhere was added.\n"
    Runbook = "Remove the overly permissive Network ACL entry and add a new entry with more restrictive permissions.\n"
    Reference = "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html#nacl-rules"
    SummaryAttributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    Tests = aws_cloud_trail_network_acl_permissive_entry_tests

    def rule(self, event):
        # Only check successful actions creating a new Network ACL entry
        if not aws_cloudtrail_success(event) or event.get("eventName") != "CreateNetworkAclEntry":
            return False
        # Check if this new NACL entry is allowing traffic from anywhere
        return (
            deep_get(event, "requestParameters", "cidrBlock") == "0.0.0.0/0"
            and deep_get(event, "requestParameters", "ruleAction") == "allow"
            and (deep_get(event, "requestParameters", "egress") is False)
        )

    def alert_context(self, event):
        return aws_rule_context(event)
