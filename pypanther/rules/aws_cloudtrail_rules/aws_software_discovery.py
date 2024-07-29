from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get

aws_software_discovery_tests: list[RuleTest] = [
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
            "p_any_aws_account_ids": ["853509373758"],
            "p_any_aws_arns": [
                "arn:aws:iam::853509373758:role/PantherAuditRole-us-east-2",
                "arn:aws:sts::853509373758:assumed-role/PantherAuditRole-us-east-2/1634605518650090138",
            ],
            "p_any_ip_addresses": ["3.16.40.237"],
            "p_event_time": "2021-10-19 01:06:59",
            "p_log_type": "AWS.CloudTrail",
            "p_parse_time": "2021-10-19 01:11:10.412",
            "p_row_id": "eabaceda7842c2b2e7a398f40cc150",
            "p_source_id": "5f9f0f60-9c56-4027-b93a-8bab3019f0f1",
            "p_source_label": "Hosted - Cloudtrail - KoS",
            "readOnly": True,
            "recipientAccountId": "853509373758",
            "requestID": "43efad11-bb40-43df-ad25-c8e7f0bfdc7a",
            "requestParameters": {
                "filterSet": {},
                "securityGroupIdSet": {"items": [{"groupId": "sg-01e29ae063f5f63a0"}]},
                "securityGroupSet": {},
            },
            "sourceIPAddress": "3.16.40.237",
            "userAgent": "aws-sdk-go/1.40.21 (go1.17; linux; amd64) exec-env/AWS_Lambda_go1.x",
            "userIdentity": {
                "accessKeyId": "ASIA4NOI7P47DJPFAXF2",
                "accountId": "853509373758",
                "arn": "arn:aws:sts::853509373758:assumed-role/PantherAuditRole-us-east-2/1634605518650090138",
                "principalId": "AROA4NOI7P47OHH3NQORX:1634605518650090138",
                "sessionContext": {
                    "attributes": {"creationDate": "2021-10-19T01:05:18Z", "mfaAuthenticated": "false"},
                    "sessionIssuer": {
                        "accountId": "853509373758",
                        "arn": "arn:aws:iam::853509373758:role/PantherAuditRole-us-east-2",
                        "principalId": "AROA4NOI7P47OHH3NQORX",
                        "type": "Role",
                        "userName": "PantherAuditRole-us-east-2",
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
    dedup_period_minutes = 360
    log_types = [LogType.AWS_CLOUDTRAIL]
    id = "AWS.Software.Discovery-prototype"
    threshold = 50
    tests = aws_software_discovery_tests
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
        return f"User [{deep_get(event, 'userIdentity', 'principalId')}] performed a [{event.get('eventName')}] action in AWS account [{event.get('recipientAccountId')}]."

    def dedup(self, event):
        return deep_get(event, "userIdentity", "principalId", default="NO_PRINCIPAL_ID_FOUND")

    def alert_context(self, event):
        return aws_rule_context(event)
