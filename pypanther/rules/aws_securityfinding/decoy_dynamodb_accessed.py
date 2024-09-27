from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class DecoyDynamoDBAccessed(Rule):
    id = "Decoy.DynamoDB.Accessed-prototype"
    display_name = "Decoy DynamoDB Accessed"
    enabled = False
    log_types = [LogType.AWS_SECURITY_FINDING_FORMAT]
    default_severity = Severity.HIGH
    default_description = "Actor accessed Decoy DynamoDB"
    default_reference = "https://aws.amazon.com/blogs/security/how-to-detect-suspicious-activity-in-your-aws-account-by-using-private-decoy-resources/"
    inline_filters = [{"All": []}]

    def rule(self, event):
        # List of suspicious API events
        # NOTE: There may be more API events that's not listed
        suspicious_api_events = [
            "BatchExecuteStatement",
            "BatchGetItem",
            "BatchWriteItem",
            "DeleteItem",
            "ExecuteStatement",
            "ExecuteTransaction",
            "GetItem",
            "PutItem",
            "Query",
            "Scan",
            "TransactGetItems",
            "TransactWriteItems",
            "UpdateItem",
        ]
        # Return True if the API value is in the list of suspicious API events
        if event["GeneratorId"] == "dynamodb.amazonaws.com":
            # Extract the API value from the event
            api_value = event["Action"]["AwsApiCallAction"]["Api"]
            return api_value in suspicious_api_events
        return False

    def title(self, event):
        # (Optional) Return a string which will be shown as the alert title.
        # If no 'dedup' function is defined, the return value of this method will act as dedup string.
        # NOTE: Not sure if the offending actor Id will always be in the 0th index of Resources
        # It's possible to just return the Title as a whole string
        secret = event["Resources"][0]["Id"]
        return f"Suspicious activity detected accessing private decoy DynamoDB table {secret}"

    tests = [
        RuleTest(
            name="DynamoDB-Decoy-Accessed",
            expected_result=True,
            log={
                "Action": {
                    "ActionType": "AWS_API_CALL",
                    "AwsApiCallAction": {
                        "Api": "Scan",
                        "CallerType": "remoteIp",
                        "DomainDetails": {},
                        "RemoteIpDetails": {
                            "City": {},
                            "Country": {},
                            "GeoLocation": {},
                            "IpAddressV4": "11.111.11.111",
                            "Organization": {},
                        },
                        "ServiceName": "dynamodb.amazonaws.com",
                    },
                    "DnsRequestAction": {},
                    "NetworkConnectionAction": {"LocalPortDetails": {}, "RemotePortDetails": {}},
                    "PortProbeAction": {},
                },
                "AwsAccountId": "123456789012",
                "CompanyName": "Custom",
                "CreatedAt": "2024-05-24 22:53:24.000000000",
                "Description": "Private decoy DynamoDB table arn:aws:dynamodb:us-east-1:123456789012:table/Panther-DataTable was accessed by arn:aws:iam::123456789012:user/tester. This DynamoDB table has been provisioned to monitor and generate security events when accessed and can be an indicator of unintended or unauthorized access to your AWS Account.",
                "FindingProviderFields": {
                    "Severity": {"Label": "HIGH", "Normalized": 70},
                    "Types": ["Unusual Behaviors"],
                },
                "GeneratorId": "dynamodb.amazonaws.com",
                "Id": "1abc2de3-69ea-4e15-91c6-27eb4a07bd21",
                "ProcessedAt": "2024-05-24T22:53:41.884Z",
                "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
                "ProductFields": {
                    "Custom/DecoyDetector/apiResult": "SUCCESS",
                    "Custom/DecoyDetector/requestID": "ab1cd234-1986-4c45-8546-fdb1776e23b0",
                    "Custom/DecoyDetector/userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                    "aws/securityhub/CompanyName": "Personal",
                    "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default/1abc2de3-69ea-4e15-91c6-27eb4a07bd21",
                    "aws/securityhub/ProductName": "Default",
                },
                "ProductName": "DecoyDetector",
                "RecordState": "ACTIVE",
                "Region": "us-east-1",
                "Resources": [
                    {
                        "Id": "<id>",
                        "Partition": "aws",
                        "Region": "us-east-1",
                        "ResourceRole": "Target",
                        "Type": "AwsDynamoDbTable",
                    },
                    {
                        "Details": {
                            "AwsIamAccessKey": {
                                "AccessKeyId": "ABC9ONWNS3155VIEJC8U",
                                "AccountId": "123456789012",
                                "PrincipalId": "ABC9ONWNS3155VIEJC8U:john.doe",
                                "PrincipalType": "AssumedRole",
                                "SessionContext": {
                                    "Attributes": {"CreationDate": "2024-05-24T22:32:38Z", "MfaAuthenticated": False},
                                    "SessionIssuer": {
                                        "AccountId": "123456789012",
                                        "Arn": "arn:aws:iam::123456789012:user/tester",
                                        "PrincipalId": "tester",
                                        "Type": "Role",
                                        "UserName": "user/tester",
                                    },
                                },
                            },
                        },
                        "Id": "ABC9ONWNS3155VIEJC8U",
                        "Partition": "aws",
                        "Region": "us-east-1",
                        "ResourceRole": "Actor",
                        "Type": "AwsIamAccessKey",
                    },
                    {
                        "Id": "arn:aws:iam::123456789012:user/tester",
                        "Partition": "aws",
                        "Region": "us-east-1",
                        "ResourceRole": "Actor",
                        "Type": "AwsIamRole",
                    },
                ],
                "SchemaVersion": "2018-10-08",
                "Severity": {"Label": "HIGH", "Normalized": 70},
                "Title": "Suspicious activity detected accessing private decoy DynamoDB table arn:aws:dynamodb:us-east-1:123456789012:table/Panther-DataTable",
                "Types": ["Unusual Behaviors"],
                "UpdatedAt": "2024-05-24 22:53:24.000000000",
                "Workflow": {"Status": "NEW"},
                "WorkflowState": "NEW",
                "p_any_actor_ids": [],
                "p_any_aws_account_ids": [],
                "p_any_aws_arns": [],
                "p_any_ip_addresses": [],
                "p_any_trace_ids": [],
                "p_any_usernames": [],
                "p_event_time": "2024-05-24 22:53:24.000000000",
                "p_log_type": "AWS.SecurityFindingFormat",
                "p_parse_time": "2024-05-24 22:55:04.312964001",
                "p_row_id": "8e1c8ebd709fb49e9eb5a1c61ff1a303",
                "p_schema_version": 0,
                "p_source_id": "e29fd64f-53d9-43ab-92ca-575a8af289e6",
                "p_source_label": "AWS Security Hub",
                "p_udm": {},
            },
        ),
        RuleTest(
            name="DynamoDB-Decoy-Not-Accessed",
            expected_result=False,
            log={
                "Action": {
                    "ActionType": "AWS_API_CALL",
                    "AwsApiCallAction": {
                        "Api": "DescribeEndpoints",
                        "CallerType": "remoteIp",
                        "DomainDetails": {},
                        "RemoteIpDetails": {
                            "City": {},
                            "Country": {},
                            "GeoLocation": {},
                            "IpAddressV4": "11.111.11.111",
                            "Organization": {},
                        },
                        "ServiceName": "dynamodb.amazonaws.com",
                    },
                    "DnsRequestAction": {},
                    "NetworkConnectionAction": {"LocalPortDetails": {}, "RemotePortDetails": {}},
                    "PortProbeAction": {},
                },
                "AwsAccountId": "123456789012",
                "CompanyName": "Custom",
                "CreatedAt": "2024-05-24 22:53:24.000000000",
                "Description": "Private decoy DynamoDB table arn:aws:dynamodb:us-east-1:123456789012:table/Panther-DataTable was not accessed by arn:aws:iam::123456789012:user/tester. This DynamoDB table has been provisioned to monitor and generate security events when accessed and can be an indicator of unintended or unauthorized access to your AWS Account.",
                "FindingProviderFields": {
                    "Severity": {"Label": "HIGH", "Normalized": 70},
                    "Types": ["Unusual Behaviors"],
                },
                "GeneratorId": "dynamodb.amazonaws.com",
                "Id": "1abc2de3-69ea-4e15-91c6-27eb4a07bd21",
                "ProcessedAt": "2024-05-24T22:53:41.884Z",
                "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
                "ProductFields": {
                    "Custom/DecoyDetector/apiResult": "SUCCESS",
                    "Custom/DecoyDetector/requestID": "ab1cd234-1986-4c45-8546-fdb1776e23b0",
                    "Custom/DecoyDetector/userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                    "aws/securityhub/CompanyName": "Personal",
                    "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default/1abc2de3-69ea-4e15-91c6-27eb4a07bd21",
                    "aws/securityhub/ProductName": "Default",
                },
                "ProductName": "DecoyDetector",
                "RecordState": "ACTIVE",
                "Region": "us-east-1",
                "Resources": [
                    {
                        "Id": "<id>",
                        "Partition": "aws",
                        "Region": "us-east-1",
                        "ResourceRole": "Target",
                        "Type": "AwsDynamoDbTable",
                    },
                    {
                        "Details": {
                            "AwsIamAccessKey": {
                                "AccessKeyId": "ABC9ONWNS3155VIEJC8U",
                                "AccountId": "123456789012",
                                "PrincipalId": "ABC9ONWNS3155VIEJC8U:john.doe",
                                "PrincipalType": "AssumedRole",
                                "SessionContext": {
                                    "Attributes": {"CreationDate": "2024-05-24T22:32:38Z", "MfaAuthenticated": False},
                                    "SessionIssuer": {
                                        "AccountId": "123456789012",
                                        "Arn": "arn:aws:iam::123456789012:user/tester",
                                        "PrincipalId": "tester",
                                        "Type": "Role",
                                        "UserName": "user/tester",
                                    },
                                },
                            },
                        },
                        "Id": "ABC9ONWNS3155VIEJC8U",
                        "Partition": "aws",
                        "Region": "us-east-1",
                        "ResourceRole": "Actor",
                        "Type": "AwsIamAccessKey",
                    },
                    {
                        "Id": "arn:aws:iam::123456789012:user/tester",
                        "Partition": "aws",
                        "Region": "us-east-1",
                        "ResourceRole": "Actor",
                        "Type": "AwsIamRole",
                    },
                ],
                "SchemaVersion": "2018-10-08",
                "Severity": {"Label": "HIGH", "Normalized": 70},
                "Title": "Non-Suspicious activity detected accessing private decoy DynamoDB table arn:aws:dynamodb:us-east-1:123456789012:table/Panther-DataTable",
                "Types": ["Unusual Behaviors"],
                "UpdatedAt": "2024-05-24 22:53:24.000000000",
                "Workflow": {"Status": "NEW"},
                "WorkflowState": "NEW",
                "p_any_actor_ids": [],
                "p_any_aws_account_ids": [],
                "p_any_aws_arns": [],
                "p_any_ip_addresses": [],
                "p_any_trace_ids": [],
                "p_any_usernames": [],
                "p_event_time": "2024-05-24 22:53:24.000000000",
                "p_log_type": "AWS.SecurityFindingFormat",
                "p_parse_time": "2024-05-24 22:55:04.312964001",
                "p_row_id": "8e1c8ebd709fb49e9eb5a1c61ff1a303",
                "p_schema_version": 0,
                "p_source_id": "e29fd64f-53d9-43ab-92ca-575a8af289e6",
                "p_source_label": "AWS Security Hub",
                "p_udm": {},
            },
        ),
    ]
