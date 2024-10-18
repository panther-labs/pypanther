from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSEC2RouteTableModified(Rule):
    id = "AWS.EC2.RouteTableModified-prototype"
    display_name = "EC2 Route Table Modified"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Exfiltration:Exfiltration Over Alternative Protocol"]
    reports = {"CIS": ["3.13"], "MITRE ATT&CK": ["TA0010:T1048"]}
    default_severity = Severity.INFO
    default_description = "An EC2 Route Table was modified."
    default_runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-ec2-route-table-modified"
    default_reference = "https://docs.aws.amazon.com/vpc/latest/userguide/WorkWithRouteTables.html"
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    # API calls that are indicative of an EC2 Route Table modification
    EC2_RT_MODIFIED_EVENTS = {
        "CreateRoute",
        "CreateRouteTable",
        "ReplaceRoute",
        "ReplaceRouteTableAssociation",
        "DeleteRouteTable",
        "DeleteRoute",
        "DisassociateRouteTable",
    }

    def rule(self, event):
        return aws_cloudtrail_success(event) and event.get("eventName") in self.EC2_RT_MODIFIED_EVENTS

    def dedup(self, event):
        return event.get("recipientAccountId")

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Route Table Modified",
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
                "eventName": "CreateRoute",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.ec2.amazonaws.com",
                "requestParameters": {
                    "routeTableId": "rtb-1",
                    "destinationCidrBlock": "0.0.0.0/0",
                    "gatewayId": "igw-1",
                },
                "responseElements": {"requestID": "1", "_return": True},
                "requestID": "1",
                "eventID": "1",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="Route Table Not Modified",
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
                "eventName": "DescribeRouteTables",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla",
                "requestParameters": {
                    "routeTableIdSet": {},
                    "filterSet": {"items": [{"name": "resource-id", "valueSet": {"items": [{"value": "vpc-1"}]}}]},
                },
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="Error Modifying Route Table",
            expected_result=False,
            log={
                "errorCode": "Blocked",
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
                "eventName": "CreateRoute",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.ec2.amazonaws.com",
                "requestParameters": {
                    "routeTableId": "rtb-1",
                    "destinationCidrBlock": "0.0.0.0/0",
                    "gatewayId": "igw-1",
                },
                "responseElements": {"requestID": "1", "_return": True},
                "requestID": "1",
                "eventID": "1",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
    ]
