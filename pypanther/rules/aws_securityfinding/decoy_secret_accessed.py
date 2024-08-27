from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

decoy_secret_accessed_tests: list[RuleTest] = [
    RuleTest(
        name="Secret-Decoy-Accessed",
        expected_result=True,
        log={
            "Action": {
                "ActionType": "AWS_API_CALL",
                "AwsApiCallAction": {
                    "Api": "Decrypt",
                    "CallerType": "remoteIp",
                    "DomainDetails": {},
                    "ServiceName": "kms.amazonaws.com",
                },
                "DnsRequestAction": {},
                "NetworkConnectionAction": {"LocalPortDetails": {}, "RemotePortDetails": {}},
                "PortProbeAction": {},
            },
            "AwsAccountId": "123456789012",
            "CompanyName": "Custom",
            "CreatedAt": "2024-05-23 20:49:02.000000000",
            "Description": "Private decoy secret arn:aws:secretsmanager:us-east-1:123456789012:secret:Dummy-Secret-ab12cde34f was accessed by arn:aws:iam::123456789012:user/tester. This secret has been provisioned to monitor and generate security events when accessed and can be an indicator of unintended or unauthorized access to your AWS Account.",
            "FindingProviderFields": {"Severity": {"Label": "HIGH", "Normalized": 70}, "Types": ["Unusual Behaviors"]},
            "GeneratorId": "secretsmanager.amazonaws.com",
            "Id": "1abc2de3-69ea-4e15-91c6-27eb4a07bd21",
            "ProcessedAt": "2024-05-23T20:49:08.396Z",
            "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
            "ProductFields": {
                "Custom/DecoyDetector/apiResult": "SUCCESS",
                "Custom/DecoyDetector/requestID": "ab1cd234-1986-4c45-8546-fdb1776e23b0",
                "Custom/DecoyDetector/userAgent": "secretsmanager.amazonaws.com",
                "aws/securityhub/CompanyName": "Personal",
                "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default/1abc2de3-69ea-4e15-91c6-27eb4a07bd21",
                "aws/securityhub/ProductName": "Default",
            },
            "ProductName": "DecoyDetector",
            "RecordState": "ACTIVE",
            "Region": "us-east-1",
            "Resources": [
                {
                    "Id": "arn:aws:secretsmanager:us-east-1:123456789012:secret:Dummy-Secret-ab12cde34f",
                    "Partition": "aws",
                    "Region": "us-east-1",
                    "ResourceRole": "Target",
                    "Tags": {
                        "aws:cloudformation:logical-id": "DummySecret",
                        "aws:cloudformation:stack-id": "arn:aws:cloudformation:us-east-1:123456789012:stack/Panther/ab1cd123-1986-4c45-8546-fdb1776e23b0",
                        "aws:cloudformation:stack-name": "Panther",
                    },
                    "Type": "AwsSecretsManagerSecret",
                },
                {
                    "Id": "arn:aws:kms:us-east-1:123456789012:key/1abc2de3-69ea-4e15-91c6-27eb4a07bd21",
                    "Partition": "aws",
                    "Region": "us-east-1",
                    "ResourceRole": "Target",
                    "Type": "AwsKmsKey",
                },
                {
                    "Details": {
                        "AwsIamAccessKey": {
                            "AccessKeyId": "ABC12DEFSG3455VIEJC8U",
                            "AccountId": "123456789012",
                            "PrincipalId": "ABC12DEFSG3455VIEJC8U:john.doe",
                            "PrincipalType": "AssumedRole",
                            "SessionContext": {
                                "Attributes": {"CreationDate": "2024-05-23T20:20:57Z", "MfaAuthenticated": False},
                                "SessionIssuer": {
                                    "AccountId": "123456789012",
                                    "Arn": "arn:aws:iam::123456789012:user/tester",
                                    "PrincipalId": "ABC12DEFSG3455VIEJC8U",
                                    "Type": "Role",
                                    "UserName": "tester",
                                },
                            },
                        },
                    },
                    "Id": "ABC12DEFSG3455VIEJC8U",
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
            "Title": "Suspicious activity detected accessing private decoy secret arn:aws:secretsmanager:us-east-1:123456789012:secret:Dummy-Secret-ab12cde34f",
            "Types": ["Unusual Behaviors"],
            "UpdatedAt": "2024-05-23 20:49:02.000000000",
            "Workflow": {"Status": "NEW"},
            "WorkflowState": "NEW",
            "p_any_actor_ids": [],
            "p_any_aws_account_ids": [],
            "p_any_aws_arns": [],
            "p_any_trace_ids": [],
            "p_any_usernames": [],
            "p_event_time": "2024-05-23 20:49:02.000000000",
            "p_log_type": "AWS.SecurityFindingFormat",
            "p_parse_time": "2024-05-23 20:55:04.316376687",
            "p_row_id": "d2b6e541507bace8c6c2b6c31fcedc10",
            "p_schema_version": 0,
            "p_source_id": "e29fd64f-53d9-43ab-92ca-575a8af289e6",
            "p_source_label": "AWS Security Hub test events",
            "p_udm": {},
        },
    ),
    RuleTest(
        name="Secret-Decoy-Listed-Not-Accessed",
        expected_result=False,
        log={
            "Action": {
                "ActionType": "AWS_API_CALL",
                "AwsApiCallAction": {
                    "Api": "ListKeys",
                    "CallerType": "remoteIp",
                    "DomainDetails": {},
                    "ServiceName": "kms.amazonaws.com",
                },
                "DnsRequestAction": {},
                "NetworkConnectionAction": {"LocalPortDetails": {}, "RemotePortDetails": {}},
                "PortProbeAction": {},
            },
            "AwsAccountId": "123456789012",
            "CompanyName": "Custom",
            "CreatedAt": "2024-05-23 20:49:02.000000000",
            "Description": "Private decoy secret arn:aws:secretsmanager:us-east-1:123456789012:secret:Dummy-Secret-ab12cde34f was not accessed by arn:aws:iam::123456789012:user/tester. This secret has been provisioned to monitor and generate security events when accessed and can be an indicator of unintended or unauthorized access to your AWS Account.",
            "FindingProviderFields": {"Severity": {"Label": "HIGH", "Normalized": 70}, "Types": ["Unusual Behaviors"]},
            "GeneratorId": "secretsmanager.amazonaws.com",
            "Id": "1abc2de3-69ea-4e15-91c6-27eb4a07bd21",
            "ProcessedAt": "2024-05-23T20:49:08.396Z",
            "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
            "ProductFields": {
                "Custom/DecoyDetector/apiResult": "SUCCESS",
                "Custom/DecoyDetector/requestID": "ab1cd234-1986-4c45-8546-fdb1776e23b0",
                "Custom/DecoyDetector/userAgent": "secretsmanager.amazonaws.com",
                "aws/securityhub/CompanyName": "Personal",
                "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default/1abc2de3-69ea-4e15-91c6-27eb4a07bd21",
                "aws/securityhub/ProductName": "Default",
            },
            "ProductName": "DecoyDetector",
            "RecordState": "ACTIVE",
            "Region": "us-east-1",
            "Resources": [
                {
                    "Id": "arn:aws:secretsmanager:us-east-1:123456789012:secret:Dummy-Secret-ab12cde34f",
                    "Partition": "aws",
                    "Region": "us-east-1",
                    "ResourceRole": "Target",
                    "Tags": {
                        "aws:cloudformation:logical-id": "DummySecret",
                        "aws:cloudformation:stack-id": "arn:aws:cloudformation:us-east-1:123456789012:stack/Panther/ab1cd123-1986-4c45-8546-fdb1776e23b0",
                        "aws:cloudformation:stack-name": "Panther",
                    },
                    "Type": "AwsSecretsManagerSecret",
                },
                {
                    "Id": "arn:aws:kms:us-east-1:123456789012:key/1abc2de3-69ea-4e15-91c6-27eb4a07bd21",
                    "Partition": "aws",
                    "Region": "us-east-1",
                    "ResourceRole": "Target",
                    "Type": "AwsKmsKey",
                },
                {
                    "Details": {
                        "AwsIamAccessKey": {
                            "AccessKeyId": "ABC12DEFSG3455VIEJC8U",
                            "AccountId": "123456789012",
                            "PrincipalId": "ABC12DEFSG3455VIEJC8U:john.doe",
                            "PrincipalType": "AssumedRole",
                            "SessionContext": {
                                "Attributes": {"CreationDate": "2024-05-23T20:20:57Z", "MfaAuthenticated": False},
                                "SessionIssuer": {
                                    "AccountId": "123456789012",
                                    "Arn": "arn:aws:iam::123456789012:user/tester",
                                    "PrincipalId": "ABC12DEFSG3455VIEJC8U",
                                    "Type": "Role",
                                    "UserName": "tester",
                                },
                            },
                        },
                    },
                    "Id": "ABC12DEFSG3455VIEJC8U",
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
            "Title": "Non-Suspicious activity detected accessing private decoy secret arn:aws:secretsmanager:us-east-1:123456789012:secret:Dummy-Secret-ab12cde34f",
            "Types": ["Unusual Behaviors"],
            "UpdatedAt": "2024-05-23 20:49:02.000000000",
            "Workflow": {"Status": "NEW"},
            "WorkflowState": "NEW",
            "p_any_actor_ids": [],
            "p_any_aws_account_ids": [],
            "p_any_aws_arns": [],
            "p_any_trace_ids": [],
            "p_any_usernames": [],
            "p_event_time": "2024-05-23 20:49:02.000000000",
            "p_log_type": "AWS.SecurityFindingFormat",
            "p_parse_time": "2024-05-23 20:55:04.316376687",
            "p_row_id": "d2b6e541507bace8c6c2b6c31fcedc10",
            "p_schema_version": 0,
            "p_source_id": "e29fd64f-53d9-43ab-92ca-575a8af289e6",
            "p_source_label": "AWS Security Hub test events",
            "p_udm": {},
        },
    ),
]


@panther_managed
class DecoySecretAccessed(Rule):
    id = "Decoy.Secret.Accessed-prototype"
    display_name = "Decoy Secret Accessed"
    enabled = False
    log_types = [LogType.AWS_SECURITY_FINDING_FORMAT]
    default_severity = Severity.HIGH
    default_description = "Actor accessed Secrets Manager decoy secret"
    default_reference = "https://aws.amazon.com/blogs/security/how-to-detect-suspicious-activity-in-your-aws-account-by-using-private-decoy-resources/"
    inline_filters = [{"All": []}]
    tests = decoy_secret_accessed_tests

    def rule(self, event):
        # List of suspicious API events
        # NOTE: There may be more API events that's not listed
        suspicious_api_events = ["Decrypt", "Encrypt", "GenerateDataKey"]
        # Return True if the API value is in the list of suspicious API events
        if event["GeneratorId"] == "secretsmanager.amazonaws.com":
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
        return f"Suspicious activity detected accessing private decoy secret {secret}"
