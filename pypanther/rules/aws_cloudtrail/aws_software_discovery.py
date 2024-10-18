from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSSoftwareDiscovery(Rule):
    default_description = (
        "A user is obtaining a list of security software, configurations, defensive tools, and sensors that are in AWS."
    )
    display_name = "AWS Software Discovery"
    enabled = False
    default_reference = "https://attack.mitre.org/techniques/T1518/001/"
    tags = ["Configuration Required"]
    reports = {"MITRE ATT&CK": ["TA0007:T1518"]}
    default_severity = Severity.INFO
    create_alert = False
    dedup_period_minutes = 360
    log_types = [LogType.AWS_CLOUDTRAIL]
    id = "AWS.Software.Discovery-prototype"
    threshold = 50
    DISCOVERY_EVENTS = [
        "ListDocuments",
        "ListMembers",
        "DescribeProducts",
        "DescribeStandards",
        "DescribeStandardsControls",
        "DescribeInstanceInformation",
        "DescribeSecurityGroups",
        "DescribeSecurityGroupRules",
        "DescribeSecurityGroupReferences",
        "DescribeSubnets",
        "DescribeHub",
        "ListFirewalls",
        "ListRuleGroups",
        "ListFirewallPolicies",
        "DescribeFirewall",
        "DescribeFirewallPolicy",
        "DescribeLoggingConfiguration",
        "DescribeResourcePolicy",
        "DescribeRuleGroup",
    ]

    def rule(self, event):
        return event.get("eventName") in self.DISCOVERY_EVENTS

    def title(self, event):
        return f"User [{event.deep_get('userIdentity', 'principalId')}] performed a [{event.get('eventName')}] action in AWS account [{event.get('recipientAccountId')}]."

    def dedup(self, event):
        return event.deep_get("userIdentity", "principalId", default="NO_PRINCIPAL_ID_FOUND")

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Discovery Event Names",
            expected_result=True,
            log={
                "awsRegion": "us-west-2",
                "eventID": "6faccad9-b6ae-4549-8e39-03430cbce2aa",
                "eventName": "DescribeSecurityGroups",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2021-10-19 01:06:59",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_any_aws_account_ids": ["123456789012"],
                "p_any_aws_arns": [
                    "arn:aws:iam::123456789012:role/ExampleRole-us-east-2",
                    "arn:aws:sts::123456789012:assumed-role/ExampleRole-us-east-2/153151351351351",
                ],
                "p_any_ip_addresses": ["12.34.56.78"],
                "p_event_time": "2021-10-19 01:06:59",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2021-10-19 01:11:10.412",
                "p_row_id": "eabaceda7842c2b2e7a398f40cc150",
                "p_source_id": "5f9f0f60-9c56-4027-b93a-8bab3019f0f1",
                "p_source_label": "Hosted - Cloudtrail - XYZ",
                "readOnly": True,
                "recipientAccountId": "123456789012",
                "requestID": "43efad11-bb40-43df-ad25-c8e7f0bfdc7a",
                "requestParameters": {
                    "filterSet": {},
                    "securityGroupIdSet": {"items": [{"groupId": "sg-01e29ae063f5f63a0"}]},
                    "securityGroupSet": {},
                },
                "sourceIPAddress": "12.34.56.78",
                "userAgent": "aws-sdk-go/1.40.21 (go1.17; linux; amd64) exec-env/AWS_Lambda_go1.x",
                "userIdentity": {
                    "accessKeyId": "ASIA153151351351351",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/ExampleRole-us-east-2/153151351351351",
                    "principalId": "AROA4NOI7P47OHH3NQORX:153151351351351",
                    "sessionContext": {
                        "attributes": {"creationDate": "2021-10-19T01:05:18Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/ExampleRole-us-east-2",
                            "principalId": "AROA153151351351351",
                            "type": "Role",
                            "userName": "ExampleRole-us-east-2",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Non Discovery Event Names",
            expected_result=False,
            log={
                "apiVersion": "2012-08-10",
                "awsRegion": "us-east-1",
                "eventCategory": "Data",
                "eventID": "9b666120-d5f9-4ca8-b158-3cd53e4c48bd",
                "eventName": "GetRecords",
                "eventSource": "dynamodb.amazonaws.com",
                "eventTime": "2023-01-09 16:01:21",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": False,
            },
        ),
    ]
