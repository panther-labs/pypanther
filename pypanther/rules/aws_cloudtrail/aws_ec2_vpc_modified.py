from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSEC2VPCModified(Rule):
    id = "AWS.EC2.VPCModified-prototype"
    display_name = "EC2 VPC Modified"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Security Control", "Defense Evasion:Impair Defenses"]
    reports = {"CIS": ["3.14"], "MITRE ATT&CK": ["TA0005:T1562"]}
    default_severity = Severity.INFO
    dedup_period_minutes = 720
    default_description = "An EC2 VPC was modified."
    default_runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-ec2-vpc-modified"
    default_reference = "https://docs.aws.amazon.com/vpc/latest/userguide/configure-your-vpc.html"
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    # API calls that are indicative of an EC2 VPC modification
    EC2_VPC_MODIFIED_EVENTS = {
        "CreateVpc",
        "DeleteVpc",
        "ModifyVpcAttribute",
        "AcceptVpcPeeringConnection",
        "CreateVpcPeeringConnection",
        "DeleteVpcPeeringConnection",
        "RejectVpcPeeringConnection",
        "AttachClassicLinkVpc",
        "DetachClassicLinkVpc",
        "DisableVpcClassicLink",
        "EnableVpcClassicLink",
    }

    def rule(self, event):
        return aws_cloudtrail_success(event) and event.get("eventName") in self.EC2_VPC_MODIFIED_EVENTS

    def dedup(self, event):
        return event.get("recipientAccountId")

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="VPC Modified",
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
                "eventName": "CreateVpc",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.ec2.amazonaws.com",
                "requestParameters": {
                    "cidrBlock": "0.0.0.0/26",
                    "instanceTenancy": "default",
                    "amazonProvidedIpv6CidrBlock": False,
                },
                "responseElements": {
                    "requestID": "1",
                    "vpc": {
                        "vpcId": "vpc-1",
                        "state": "pending",
                        "ownerId": "123456789012",
                        "cidrBlock": "0.0.0.0/26",
                        "cidrBlockAssociationSet": {
                            "items": [
                                {
                                    "cidrBlock": "0.0.0.0/26",
                                    "associationId": "vpc-cidr-assoc-1",
                                    "cidrBlockState": {"state": "associated"},
                                },
                            ],
                        },
                        "ipv6CidrBlockAssociationSet": {},
                        "dhcpOptionsId": "dopt-1",
                        "instanceTenancy": "default",
                        "tagSet": {},
                        "isDefault": False,
                    },
                },
                "requestID": "1",
                "eventID": "1",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="VPC Not Modified",
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
                "eventName": "DescribeVpcs",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla",
                "requestParameters": {"vpcSet": {}, "filterSet": {}},
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="Error Modifying VPC",
            expected_result=False,
            log={
                "errorCode": "UnknownParameter",
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
                "eventName": "CreateVpc",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.ec2.amazonaws.com",
                "requestParameters": {
                    "cidrBlock": "0.0.0.0/26",
                    "instanceTenancy": "default",
                    "amazonProvidedIpv6CidrBlock": False,
                },
                "responseElements": {
                    "requestID": "1",
                    "vpc": {
                        "vpcId": "vpc-1",
                        "state": "pending",
                        "ownerId": "123456789012",
                        "cidrBlock": "0.0.0.0/26",
                        "cidrBlockAssociationSet": {
                            "items": [
                                {
                                    "cidrBlock": "0.0.0.0/26",
                                    "associationId": "vpc-cidr-assoc-1",
                                    "cidrBlockState": {"state": "associated"},
                                },
                            ],
                        },
                        "ipv6CidrBlockAssociationSet": {},
                        "dhcpOptionsId": "dopt-1",
                        "instanceTenancy": "default",
                        "tagSet": {},
                        "isDefault": False,
                    },
                },
                "requestID": "1",
                "eventID": "1",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
    ]
