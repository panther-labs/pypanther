from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context
from pypanther.helpers.panther_default import aws_cloudtrail_success
from pypanther.log_types import LogType

awsec2_security_group_modified_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Security Group Modified",
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
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "1111",
                        "arn": "arn:aws:iam::123456789012:role/tester",
                        "accountId": "123456789012",
                        "userName": "tester",
                    },
                    "webIdFederationData": {},
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-01-01T00:00:00Z",
                    },
                },
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.ec2.amazonaws.com",
            "requestParameters": {
                "groupId": "sg-1",
                "ipPermissions": {
                    "items": [
                        {
                            "ipProtocol": "tcp",
                            "fromPort": 22,
                            "toPort": 22,
                            "groups": {},
                            "ipRanges": {
                                "items": [{"cidrIp": "127.0.0.1/32", "description": "SSH for me"}]
                            },
                            "ipv6Ranges": {},
                            "prefixListIds": {},
                        }
                    ]
                },
            },
            "responseElements": {"requestID": "1", "_return": True},
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    PantherRuleTest(
        Name="Security Group Not Modified",
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
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "1111",
                        "arn": "arn:aws:iam::123456789012:role/tester",
                        "accountId": "123456789012",
                        "userName": "tester",
                    },
                    "webIdFederationData": {},
                    "attributes": {
                        "mfaAuthenticated": "false",
                        "creationDate": "2019-01-01T00:00:00Z",
                    },
                },
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeSecurityGroups",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla",
            "requestParameters": {
                "securityGroupSet": {},
                "securityGroupIdSet": {},
                "filterSet": {
                    "items": [{"name": "vpc-id", "valueSet": {"items": [{"value": "vpc-1"}]}}]
                },
            },
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    PantherRuleTest(
        Name="Error Mofidying Security Group",
        ExpectedResult=False,
        Log={
            "errorCode": "RequestExpired",
            "eventVersion": "1.05",
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
                    "webIdFederationData": {},
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-01-01T00:00:00Z",
                    },
                },
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.ec2.amazonaws.com",
            "requestParameters": {
                "groupId": "sg-1",
                "ipPermissions": {
                    "items": [
                        {
                            "ipProtocol": "tcp",
                            "fromPort": 22,
                            "toPort": 22,
                            "groups": {},
                            "ipRanges": {
                                "items": [{"cidrIp": "127.0.0.1/32", "description": "SSH for me"}]
                            },
                            "ipv6Ranges": {},
                            "prefixListIds": {},
                        }
                    ]
                },
            },
            "responseElements": {"requestID": "1", "_return": True},
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
]


class AWSEC2SecurityGroupModified(PantherRule):
    RuleID = "AWS.EC2.SecurityGroupModified-prototype"
    DisplayName = "EC2 Security Group Modified"
    LogTypes = [LogType.AWS_CloudTrail]
    Tags = ["AWS", "Security Control", "Defense Evasion:Impair Defenses"]
    Reports = {"CIS": ["3.1"], "MITRE ATT&CK": ["TA0005:T1562"]}
    Severity = PantherSeverity.Info
    DedupPeriodMinutes = 720
    Description = "An EC2 Security Group was modified.\n"
    Runbook = (
        "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-ec2-securitygroup-modified"
    )
    Reference = (
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/working-with-security-groups.html"
    )
    SummaryAttributes = [
        "eventName",
        "userAgent",
        "sourceIpAddress",
        "recipientAccountId",
        "p_any_aws_arns",
    ]
    Tests = awsec2_security_group_modified_tests
    # API calls that are indicative of an EC2 SecurityGroup modification
    EC2_SG_MODIFIED_EVENTS = {
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress",
        "RevokeSecurityGroupEgress",
        "CreateSecurityGroup",
        "DeleteSecurityGroup",
    }

    def rule(self, event):
        return (
            aws_cloudtrail_success(event) and event.get("eventName") in self.EC2_SG_MODIFIED_EVENTS
        )

    def dedup(self, event):
        return event.get("recipientAccountId")

    def alert_context(self, event):
        return aws_rule_context(event)
