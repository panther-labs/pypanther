from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context
from pypanther.helpers.panther_default import aws_cloudtrail_success

awsec2_network_acl_modified_tests: list[RuleTest] = [
    RuleTest(
        name="Network ACL Modified",
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
            "eventSource": "ec2.amazonaws.com",
            "eventName": "CreateNetworkAclEntry",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.ec2.amazonaws.com",
            "requestParameters": {
                "networkAclId": "acl-1",
                "ruleNumber": 500,
                "egress": True,
                "ruleAction": "allow",
                "icmpTypeCode": {},
                "portRange": {},
                "aclProtocol": "-1",
                "cidrBlock": "0.0.0.0/0",
            },
            "responseElements": {"requestID": "1", "_return": True},
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    RuleTest(
        name="Network ACL Not Modified",
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
            "eventName": "DescribeNetworkAcls",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla",
            "requestParameters": {
                "networkAclIdSet": {},
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
        name="Error Modifying Network ACL",
        expected_result=False,
        log={
            "errorCode": "InvalidCharacter",
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
            "eventSource": "ec2.amazonaws.com",
            "eventName": "CreateNetworkAclEntry",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.ec2.amazonaws.com",
            "requestParameters": {
                "networkAclId": "acl-1",
                "ruleNumber": 500,
                "egress": True,
                "ruleAction": "allow",
                "icmpTypeCode": {},
                "portRange": {},
                "aclProtocol": "-1",
                "cidrBlock": "0.0.0.0/0",
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
class AWSEC2NetworkACLModified(Rule):
    id = "AWS.EC2.NetworkACLModified-prototype"
    display_name = "EC2 Network ACL Modified"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Security Control", "Defense Evasion:Impair Defenses"]
    reports = {"CIS": ["3.11"], "MITRE ATT&CK": ["TA0005:T1562"]}
    default_severity = Severity.INFO
    default_description = "An EC2 Network ACL was modified."
    default_runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-ec2-network-acl-modified"
    default_reference = "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html#nacl-tasks"
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    tests = awsec2_network_acl_modified_tests
    # API calls that are indicative of an EC2 Network ACL modification
    EC2_NACL_MODIFIED_EVENTS = {
        "CreateNetworkAcl",
        "CreateNetworkAclEntry",
        "DeleteNetworkAcl",
        "DeleteNetworkAclEntry",
        "ReplaceNetworkAclEntry",
        "ReplaceNetworkAclAssociation",
    }

    def rule(self, event):
        return aws_cloudtrail_success(event) and event.get("eventName") in self.EC2_NACL_MODIFIED_EVENTS

    def dedup(self, event):
        return event.get("recipientAccountId")

    def alert_context(self, event):
        return aws_rule_context(event)
