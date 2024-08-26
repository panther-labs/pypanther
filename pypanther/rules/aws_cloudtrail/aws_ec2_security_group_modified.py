from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context
from pypanther.helpers.panther_default import aws_cloudtrail_success

awsec2_security_group_modified_tests: list[RuleTest] = [
    RuleTest(
        name="Security Group Modified",
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
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "1111",
                        "arn": "arn:aws:iam::123456789012:role/tester",
                        "accountId": "123456789012",
                        "userName": "tester",
                    },
                    "webIdFederationData": {},
                    "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
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
                            "ipRanges": {"items": [{"cidrIp": "127.0.0.1/32", "description": "SSH for me"}]},
                            "ipv6Ranges": {},
                            "prefixListIds": {},
                        },
                    ],
                },
            },
            "responseElements": {"requestID": "1", "_return": True},
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    RuleTest(
        name="Security Group Not Modified",
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
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "1111",
                        "arn": "arn:aws:iam::123456789012:role/tester",
                        "accountId": "123456789012",
                        "userName": "tester",
                    },
                    "webIdFederationData": {},
                    "attributes": {"mfaAuthenticated": "false", "creationDate": "2019-01-01T00:00:00Z"},
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
                "filterSet": {"items": [{"name": "vpc-id", "valueSet": {"items": [{"value": "vpc-1"}]}}]},
            },
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    RuleTest(
        name="Error Mofidying Security Group",
        expected_result=False,
        log={
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
                    "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
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
                            "ipRanges": {"items": [{"cidrIp": "127.0.0.1/32", "description": "SSH for me"}]},
                            "ipv6Ranges": {},
                            "prefixListIds": {},
                        },
                    ],
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


@panther_managed
class AWSEC2SecurityGroupModified(Rule):
    id = "AWS.EC2.SecurityGroupModified-prototype"
    display_name = "EC2 Security Group Modified"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Security Control", "Defense Evasion:Impair Defenses"]
    reports = {"CIS": ["3.1"], "MITRE ATT&CK": ["TA0005:T1562"]}
    default_severity = Severity.INFO
    dedup_period_minutes = 720
    default_description = "An EC2 Security Group was modified.\n"
    default_runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-ec2-securitygroup-modified"
    default_reference = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/working-with-security-groups.html"
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    tests = awsec2_security_group_modified_tests
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
        return aws_cloudtrail_success(event) and event.get("eventName") in self.EC2_SG_MODIFIED_EVENTS

    def dedup(self, event):
        return event.get("recipientAccountId")

    def alert_context(self, event):
        return aws_rule_context(event)
