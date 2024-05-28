from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context
from pypanther.helpers.panther_default import aws_cloudtrail_success
from pypanther.log_types import LogType

awsec2_gateway_modified_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Network Gateway Modified",
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
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-01-01T00:00:00Z",
                    },
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
            "eventName": "AttachInternetGateway",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.ec2.amazonaws.com",
            "requestParameters": {"internetGatewayId": "igw-1", "vpcId": "vpc-1"},
            "responseElements": {"requestID": "1", "_return": True},
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    PantherRuleTest(
        Name="Network Gateway Not Modified",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "1111:2222",
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
            "eventName": "DescribeRouteTables",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla",
            "requestParameters": {
                "routeTableIdSet": {},
                "filterSet": {
                    "items": [{"name": "resource-id", "valueSet": {"items": [{"value": "vpc-1"}]}}]
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
        Name="Error Modifying Network Gateway",
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
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-01-01T00:00:00Z",
                    },
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
            "eventName": "AttachInternetGateway",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "console.ec2.amazonaws.com",
            "requestParameters": {"internetGatewayId": "igw-1", "vpcId": "vpc-1"},
            "responseElements": {"requestID": "1", "_return": True},
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
]


class AWSEC2GatewayModified(PantherRule):
    RuleID = "AWS.EC2.GatewayModified-prototype"
    DisplayName = "EC2 Network Gateway Modified"
    LogTypes = [LogType.AWS_CloudTrail]
    Tags = ["AWS", "Security Control", "Defense Evasion:Impair Defenses"]
    Reports = {"CIS": ["3.12"], "MITRE ATT&CK": ["TA0005:T1562"]}
    Severity = PantherSeverity.Info
    Description = "An EC2 Network Gateway was modified."
    Runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-ec2-gateway-modified"
    Reference = "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html"
    SummaryAttributes = [
        "eventName",
        "userAgent",
        "sourceIpAddress",
        "recipientAccountId",
        "p_any_aws_arns",
    ]
    Tests = awsec2_gateway_modified_tests
    # API calls that are indicative of an EC2 Network Gateway modification
    EC2_GATEWAY_MODIFIED_EVENTS = {
        "CreateCustomerGateway",
        "DeleteCustomerGateway",
        "AttachInternetGateway",
        "CreateInternetGateway",
        "DeleteInternetGateway",
        "DetachInternetGateway",
    }

    def rule(self, event):
        return (
            aws_cloudtrail_success(event)
            and event.get("eventName") in self.EC2_GATEWAY_MODIFIED_EVENTS
        )

    def dedup(self, event):
        return event.get("recipientAccountId")

    def alert_context(self, event):
        return aws_rule_context(event)
