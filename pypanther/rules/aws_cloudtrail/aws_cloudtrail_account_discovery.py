from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class AWSCloudTrailAccountDiscovery(Rule):
    default_description = "Adversaries may attempt to get a listing of accounts on a system or within an environment. This information can help adversaries determine which accounts exist to aid in follow-on behavior."
    display_name = "AWS CloudTrail Account Discovery"
    default_reference = "https://attack.mitre.org/techniques/T1087/"
    reports = {"MITRE ATT&CK": ["TA0007:T1087"]}
    default_severity = Severity.INFO
    create_alert = False
    log_types = [LogType.AWS_CLOUDTRAIL]
    id = "AWS.CloudTrail.Account.Discovery-prototype"
    DISCOVERY_EVENTS = [
        "GetAlternateContact",
        "GetContactInformation",
        "PutAlternateContact",
        "PutContactInformation",
        "DescribeAccount",
    ]

    def rule(self, event):
        return event.get("eventName") in self.DISCOVERY_EVENTS

    def title(self, event):
        return f"User [{event.deep_get('userIdentity', 'arn')}]performed a [{event.get('eventName')}] action in AWS account [{event.get('recipientAccountId')}]."

    tests = [
        RuleTest(
            name="DescribeAccount",
            expected_result=True,
            log={
                "awsRegion": "us-east-1",
                "eventCategory": "Management",
                "eventID": "0b51d284-19f7-42cf-a103-276602aeada5",
                "eventName": "DescribeAccount",
                "eventSource": "organizations.amazonaws.com",
                "eventTime": "2022-11-21 18:06:52",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_any_aws_account_ids": ["123456789123"],
                "p_any_aws_arns": [
                    "arn:aws:iam::123456789123:role/TestUser",
                    "arn:aws:sts::123456789123:assumed-role/TestUser/test_123456789123",
                ],
                "p_any_ip_addresses": ["1.1.1.1"],
                "p_any_trace_ids": ["ASIA3JHVJH35KB7LJHV2"],
                "p_any_usernames": ["TestUser"],
                "p_event_time": "2022-11-21 18:06:52",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2022-11-21 18:07:38.9",
                "p_row_id": "824956f0377f98908684d8de14d3d612",
                "p_source_id": "5f9f0f60-9c56-4027-b93a-8bab3019f0f1",
                "p_source_label": "Cloudtrail",
                "readOnly": True,
                "recipientAccountId": "123456789123",
                "requestID": "1c40241b-c59c-4d4a-8301-b612545f9c5c",
                "requestParameters": {"accountId": "123456789123"},
                "sourceIPAddress": "1.1.1.1",
                "tlsDetails": {
                    "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "clientProvidedHostHeader": "organizations.us-east-1.amazonaws.com",
                    "tlsVersion": "TLSv1.2",
                },
                "userAgent": "Boto3/1.26.2 Python/3.10.8 Linux/4.14.294-220.533.amzn2.x86_64 exec-env/AWS_ECS_FARGATE Botocore/1.29.2",
                "userIdentity": {
                    "accessKeyId": "ASIA3JHVJH35KB7LJHV2",
                    "accountId": "123456789123",
                    "arn": "arn:aws:sts::123456789123:assumed-role/TestUser/test_123456789123",
                    "principalId": "AR0A354LKJXC87G9XC89V:test_123456789123",
                    "sessionContext": {
                        "attributes": {"creationDate": "2022-11-21T18:06:36Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "123456789123",
                            "arn": "arn:aws:iam::123456789123:role/TestUser",
                            "principalId": "AR0A354LKJXC87G9XC89V",
                            "type": "Role",
                            "userName": "TestUser",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="GetAlternateContact",
            expected_result=True,
            log={
                "awsRegion": "us-east-1",
                "eventCategory": "Management",
                "eventID": "cd05c51d-fee2-4003-b9c5-385f28ad5b29",
                "eventName": "GetAlternateContact",
                "eventSource": "billingconsole.amazonaws.com",
                "eventTime": "2022-11-23 21:06:45",
                "eventType": "AwsConsoleAction",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_any_aws_account_ids": ["123456789123"],
                "p_any_aws_arns": ["arn:aws:sts::123456789123:assumed-role/DevAdministrator/test_user"],
                "p_any_ip_addresses": ["1.1.1.1"],
                "p_any_trace_ids": ["ASIA3JHVJH35KB7LJHV2"],
                "p_event_time": "2022-11-23 21:06:45",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2022-11-23 21:08:20.503",
                "p_row_id": "be1f79935716d5c6faf68be41493e410",
                "p_source_id": "125a8146-e3ea-454b-aed7-9e08e735b670",
                "p_source_label": "CloudTrail",
                "readOnly": True,
                "recipientAccountId": "123456789123",
                "requestParameters": {"map": {}},
                "sourceIPAddress": "1.1.1.1",
                "tlsDetails": {
                    "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "clientProvidedHostHeader": "us-east-1.console.aws.amazon.com",
                    "tlsVersion": "TLSv1.2",
                },
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
                "userIdentity": {
                    "accessKeyId": "ASIA3JHVJH35KB7LJHV2",
                    "accountId": "123456789123",
                    "arn": "arn:aws:sts::123456789123:assumed-role/DevAdministrator/test_user",
                    "principalId": "AR0A354LKJXC87G9XC89V:test_user",
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="GetContactInformation",
            expected_result=True,
            log={
                "awsRegion": "us-east-1",
                "eventCategory": "Management",
                "eventID": "743a109a-3bce-4298-8828-114c11339119",
                "eventName": "GetContactInformation",
                "eventSource": "billingconsole.amazonaws.com",
                "eventTime": "2022-11-23 21:06:46",
                "eventType": "AwsConsoleAction",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_any_aws_account_ids": ["123456789123"],
                "p_any_aws_arns": ["arn:aws:sts::123456789123:assumed-role/DevAdministrator/test_user"],
                "p_any_ip_addresses": ["1.1.1.1"],
                "p_any_trace_ids": ["ASIA3JHVJH35KB7LJHV2"],
                "p_event_time": "2022-11-23 21:06:46",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2022-11-23 21:08:20.502",
                "p_row_id": "be1f79935716d5c6faf68be4148ce410",
                "p_source_id": "125a8146-e3ea-454b-aed7-9e08e735b670",
                "p_source_label": "Panther Identity Org CloudTrail",
                "readOnly": True,
                "recipientAccountId": "123456789123",
                "requestParameters": {"map": {"type": "CONTACT"}},
                "sourceIPAddress": "1.1.1.1",
                "tlsDetails": {
                    "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "clientProvidedHostHeader": "us-east-1.console.aws.amazon.com",
                    "tlsVersion": "TLSv1.2",
                },
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
                "userIdentity": {
                    "accessKeyId": "ASIA3JHVJH35KB7LJHV2",
                    "accountId": "123456789123",
                    "arn": "arn:aws:sts::123456789123:assumed-role/DevAdministrator/test_user",
                    "principalId": "AR0A354LKJXC87G9XC89V:test_user",
                    "type": "AssumedRole",
                },
            },
        ),
    ]
