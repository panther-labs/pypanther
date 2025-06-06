from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class DecoyS3Accessed(Rule):
    id = "Decoy.S3.Accessed-prototype"
    display_name = "Decoy S3 Accessed"
    enabled = False
    log_types = [LogType.AWS_SECURITY_FINDING_FORMAT]
    default_severity = Severity.HIGH
    default_description = "Actor accessed S3 Manager decoy secret"
    default_reference = "https://aws.amazon.com/blogs/security/how-to-detect-suspicious-activity-in-your-aws-account-by-using-private-decoy-resources/"
    inline_filters = [{"All": []}]

    def rule(self, event):
        # List of suspicious API events
        # NOTE: There may be more API events that's not listed
        suspicious_api_events = [
            "HeadObject",
            "GetObject",
            "GetObjectAcl",
            "GetObjectAttributes",
            "GetObjectLegalHold",
            "GetObjectLockConfiguration",
            "GetObjectRetention",
            "GetObjectTagging",
            "GetObjectTorrent",
            "PutObject",
            "PutObjectAcl",
            "PutObjectLegalHold",
            "PutObjectLockConfiguration",
            "PutObjectRetention",
            "PutObjectTagging",
            "SelectObjectContent",
            "DeleteObject",
            "DeleteObjects",
            "DeleteObjectTagging",
        ]
        # Return True if the API value is in the list of suspicious API events
        if event["GeneratorId"] == "s3.amazonaws.com":
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
        return f"Suspicious activity detected accessing private decoy S3 bucket {secret}"

    tests = [
        RuleTest(
            name="S3-Decoy-Accessed",
            expected_result=True,
            log={
                "Action": {
                    "ActionType": "AWS_API_CALL",
                    "AwsApiCallAction": {
                        "Api": "GetObject",
                        "CallerType": "remoteIp",
                        "DomainDetails": {},
                        "RemoteIpDetails": {
                            "City": {},
                            "Country": {},
                            "GeoLocation": {},
                            "IpAddressV4": "111.111.111.111",
                            "Organization": {},
                        },
                        "ServiceName": "s3.amazonaws.com",
                    },
                    "DnsRequestAction": {},
                    "NetworkConnectionAction": {"LocalPortDetails": {}, "RemotePortDetails": {}},
                    "PortProbeAction": {},
                },
                "AwsAccountId": "123456789012",
                "CompanyName": "Custom",
                "CreatedAt": "2024-05-24 00:26:57.000000000",
                "Description": "Private decoy S3 bucket panther-databucket was accessed by arn:aws:iam::123456789012:user/tester. This S3 bucket has been provisioned to monitor and generate security events when accessed and can be an indicator of unintended or unauthorized access to your AWS Account.",
                "FindingProviderFields": {
                    "Severity": {"Label": "HIGH", "Normalized": 70},
                    "Types": ["Unusual Behaviors"],
                },
                "GeneratorId": "s3.amazonaws.com",
                "Id": "ABC9ONWNS3155VIEJC8U",
                "ProcessedAt": "2024-05-24T00:27:12.237Z",
                "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
                "ProductFields": {
                    "Custom/DecoyDetector/apiResult": "SUCCESS",
                    "Custom/DecoyDetector/requestID": "ab1cd234-1986-4c45-8546-fdb1776e23b0",
                    "Custom/DecoyDetector/userAgent": "[Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36]",
                    "aws/securityhub/CompanyName": "Personal",
                    "aws/securityhub/FindingId": "arn:aws:service:region:123456789012:resource/12345ab6-436d-4d59-ac58-ed6b3127e440",
                    "aws/securityhub/ProductName": "Default",
                },
                "ProductName": "DecoyDetector",
                "RecordState": "ACTIVE",
                "Region": "us-east-1",
                "Resources": [
                    {
                        "Id": "arn:aws:s3:::panther-databucket",
                        "Partition": "aws",
                        "Region": "us-east-1",
                        "ResourceRole": "Target",
                        "Tags": {
                            "aws:cloudformation:logical-id": "DataBucket",
                            "aws:cloudformation:stack-id": "arn:aws:cloudformation:us-east-1:123456789012:stack/Panther/a1b2c345-12f6-11ef-8c74-12deb08d9ef1",
                            "aws:cloudformation:stack-name": "Panther",
                        },
                        "Type": "AwsS3Bucket",
                    },
                    {
                        "Id": "arn:aws:s3:::panther-databucket/object",
                        "Partition": "aws",
                        "Region": "us-east-1",
                        "ResourceRole": "Target",
                        "Type": "AwsS3Object",
                    },
                    {
                        "Details": {
                            "AwsIamAccessKey": {
                                "AccessKeyId": "ABCDEFG1HIJ2KLMNOPQR",
                                "AccountId": "123456789012",
                                "PrincipalId": "ABCDEFG1HIJ2KLMNOPQR:john.doe",
                                "PrincipalType": "AssumedRole",
                                "SessionContext": {
                                    "Attributes": {"CreationDate": "2024-05-23T20:20:57Z", "MfaAuthenticated": False},
                                    "SessionIssuer": {
                                        "AccountId": "123456789012",
                                        "Arn": "arn:aws:iam::123456789012:role/tester",
                                        "PrincipalId": "ABCDEFG1HIJ2KLMNOPQR",
                                        "Type": "Role",
                                        "UserName": "tester",
                                    },
                                },
                            },
                        },
                        "Id": "ABCDEFG1HIJ2KLMNOPQR",
                        "Partition": "aws",
                        "Region": "us-east-1",
                        "ResourceRole": "Actor",
                        "Type": "AwsIamAccessKey",
                    },
                    {
                        "Id": "ABCDEFG1HIJ2KLMNOPQR",
                        "Partition": "aws",
                        "Region": "us-east-1",
                        "ResourceRole": "Actor",
                        "Type": "AwsIamRole",
                    },
                ],
                "SchemaVersion": "2018-10-08",
                "Severity": {"Label": "HIGH", "Normalized": 70},
                "Title": "Suspicious activity detected accessing private decoy S3 bucket panther-databucket",
                "Types": ["Unusual Behaviors"],
                "UpdatedAt": "2024-05-24 00:26:57.000000000",
                "Workflow": {"Status": "NEW"},
                "WorkflowState": "NEW",
                "p_any_actor_ids": [],
                "p_any_aws_account_ids": [],
                "p_any_aws_arns": [],
                "p_any_ip_addresses": [],
                "p_any_trace_ids": [],
                "p_any_usernames": [],
                "p_event_time": "2024-05-24 00:26:57.000000000",
                "p_log_type": "AWS.SecurityFindingFormat",
                "p_parse_time": "2024-05-24 00:30:04.569556803",
                "p_row_id": "624c79c882affe88a1dce9c31fb68f0e",
                "p_schema_version": 0,
                "p_source_id": "e29fd64f-53d9-43ab-92ca-575a8af289e6",
                "p_source_label": "AWS Security Hub",
            },
        ),
        RuleTest(
            name="S3-Decoy-Not-Accessed",
            expected_result=False,
            log={
                "Action": {
                    "ActionType": "AWS_API_CALL",
                    "AwsApiCallAction": {
                        "Api": "ListBuckets",
                        "CallerType": "remoteIp",
                        "DomainDetails": {},
                        "RemoteIpDetails": {
                            "City": {},
                            "Country": {},
                            "GeoLocation": {},
                            "IpAddressV4": "111.111.111.111",
                            "Organization": {},
                        },
                        "ServiceName": "s3.amazonaws.com",
                    },
                    "DnsRequestAction": {},
                    "NetworkConnectionAction": {"LocalPortDetails": {}, "RemotePortDetails": {}},
                    "PortProbeAction": {},
                },
                "AwsAccountId": "123456789012",
                "CompanyName": "Custom",
                "CreatedAt": "2024-05-24 00:26:57.000000000",
                "Description": "Private decoy S3 bucket panther-databucket was not accessed by arn:aws:iam::123456789012:user/tester. This S3 bucket has been provisioned to monitor and generate security events when accessed and can be an indicator of unintended or unauthorized access to your AWS Account.",
                "FindingProviderFields": {
                    "Severity": {"Label": "HIGH", "Normalized": 70},
                    "Types": ["Unusual Behaviors"],
                },
                "GeneratorId": "s3.amazonaws.com",
                "Id": "ABC9ONWNS3155VIEJC8U",
                "ProcessedAt": "2024-05-24T00:27:12.237Z",
                "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
                "ProductFields": {
                    "Custom/DecoyDetector/apiResult": "SUCCESS",
                    "Custom/DecoyDetector/requestID": "ab1cd234-1986-4c45-8546-fdb1776e23b0",
                    "Custom/DecoyDetector/userAgent": "[Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36]",
                    "aws/securityhub/CompanyName": "Personal",
                    "aws/securityhub/FindingId": "arn:aws:service:region:123456789012:resource/12345ab6-436d-4d59-ac58-ed6b3127e440",
                    "aws/securityhub/ProductName": "Default",
                },
                "ProductName": "DecoyDetector",
                "RecordState": "ACTIVE",
                "Region": "us-east-1",
                "Resources": [
                    {
                        "Id": "arn:aws:s3:::panther-databucket",
                        "Partition": "aws",
                        "Region": "us-east-1",
                        "ResourceRole": "Target",
                        "Tags": {
                            "aws:cloudformation:logical-id": "DataBucket",
                            "aws:cloudformation:stack-id": "arn:aws:cloudformation:us-east-1:123456789012:stack/Panther/a1b2c345-12f6-11ef-8c74-12deb08d9ef1",
                            "aws:cloudformation:stack-name": "Panther",
                        },
                        "Type": "AwsS3Bucket",
                    },
                    {
                        "Id": "arn:aws:s3:::panther-databucket/object",
                        "Partition": "aws",
                        "Region": "us-east-1",
                        "ResourceRole": "Target",
                        "Type": "AwsS3Object",
                    },
                    {
                        "Details": {
                            "AwsIamAccessKey": {
                                "AccessKeyId": "ABCDEFG1HIJ2KLMNOPQR",
                                "AccountId": "123456789012",
                                "PrincipalId": "ABCDEFG1HIJ2KLMNOPQR:john.doe",
                                "PrincipalType": "AssumedRole",
                                "SessionContext": {
                                    "Attributes": {"CreationDate": "2024-05-23T20:20:57Z", "MfaAuthenticated": False},
                                    "SessionIssuer": {
                                        "AccountId": "123456789012",
                                        "Arn": "arn:aws:iam::123456789012:role/tester",
                                        "PrincipalId": "ABCDEFG1HIJ2KLMNOPQR",
                                        "Type": "Role",
                                        "UserName": "tester",
                                    },
                                },
                            },
                        },
                        "Id": "ABCDEFG1HIJ2KLMNOPQR",
                        "Partition": "aws",
                        "Region": "us-east-1",
                        "ResourceRole": "Actor",
                        "Type": "AwsIamAccessKey",
                    },
                    {
                        "Id": "ABCDEFG1HIJ2KLMNOPQR",
                        "Partition": "aws",
                        "Region": "us-east-1",
                        "ResourceRole": "Actor",
                        "Type": "AwsIamRole",
                    },
                ],
                "SchemaVersion": "2018-10-08",
                "Severity": {"Label": "HIGH", "Normalized": 70},
                "Title": "Non-Suspicious activity detected accessing private decoy S3 bucket panther-databucket",
                "Types": ["Unusual Behaviors"],
                "UpdatedAt": "2024-05-24 00:26:57.000000000",
                "Workflow": {"Status": "NEW"},
                "WorkflowState": "NEW",
                "p_any_actor_ids": [],
                "p_any_aws_account_ids": [],
                "p_any_aws_arns": [],
                "p_any_ip_addresses": [],
                "p_any_trace_ids": [],
                "p_any_usernames": [],
                "p_event_time": "2024-05-24 00:26:57.000000000",
                "p_log_type": "AWS.SecurityFindingFormat",
                "p_parse_time": "2024-05-24 00:30:04.569556803",
                "p_row_id": "624c79c882affe88a1dce9c31fb68f0e",
                "p_schema_version": 0,
                "p_source_id": "e29fd64f-53d9-43ab-92ca-575a8af289e6",
                "p_source_label": "AWS Security Hub",
            },
        ),
    ]
