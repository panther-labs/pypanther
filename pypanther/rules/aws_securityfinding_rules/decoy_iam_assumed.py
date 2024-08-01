from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

decoy_iam_assumed_tests: list[RuleTest] = [
    RuleTest(
        name="IAM-Decoy-Assumed",
        expected_result=True,
        log={
            "Action": {
                "ActionType": "AWS_API_CALL",
                "AwsApiCallAction": {
                    "Api": "AssumeRole",
                    "CallerType": "remoteIp",
                    "DomainDetails": {},
                    "RemoteIpDetails": {
                        "City": {},
                        "Country": {},
                        "GeoLocation": {},
                        "IpAddressV4": "11.1.111.11",
                        "Organization": {},
                    },
                    "ServiceName": "sts.amazonaws.com",
                },
                "DnsRequestAction": {},
                "NetworkConnectionAction": {"LocalPortDetails": {}, "RemotePortDetails": {}},
                "PortProbeAction": {},
            },
            "AwsAccountId": "123456789012",
            "CompanyName": "Custom",
            "CreatedAt": "2024-05-24 13:17:15.000000000",
            "Description": "Private decoy IAM role arn:aws:iam::123456789012:role/Dummy-Test-InfoRole-ab21cde50f was accessed by arn:aws:iam::123456789012:user/tester. This IAM role has been provisioned to monitor and generate security events when accessed and can be an indicator of unintended or unauthorized access to your AWS Account.",
            "FindingProviderFields": {"Severity": {"Label": "HIGH", "Normalized": 70}, "Types": ["Unusual Behaviors"]},
            "GeneratorId": "sts.amazonaws.com",
            "Id": "1abc2de3-69ea-4e15-91c6-27eb4a07bd21",
            "ProcessedAt": "2024-05-24T13:17:21.469Z",
            "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
            "ProductFields": {
                "Custom/DecoyDetector/apiResult": "SUCCESS",
                "Custom/DecoyDetector/requestID": "ab1cd123-1986-4c45-8546-fdb1776e23b0",
                "Custom/DecoyDetector/userAgent": "AWS Signin, aws-internal/3 aws-sdk-java/1.12.720 Linux/5.10.215-181.850.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/17.0.11+10-LTS java/17.0.11 kotlin/1.3.72 vendor/Amazon.com_Inc. cfg/retry-mode/standard cfg/auth-source#unknown",
                "aws/securityhub/CompanyName": "Personal",
                "aws/securityhub/FindingId": "arn:aws:service:region:123456789012:resource/12345ab9-436d-4d59-ac58-ed6b3127e440",
                "aws/securityhub/ProductName": "Default",
            },
            "ProductName": "DecoyDetector",
            "RecordState": "ACTIVE",
            "Region": "us-east-1",
            "Resources": [
                {
                    "Id": "arn:aws:iam::123456789012:role/Dummy-Test-InfoRole-ab21cde50f",
                    "Partition": "aws",
                    "Region": "us-east-1",
                    "ResourceRole": "Target",
                    "Type": "AwsIamRole",
                },
                {
                    "Details": {
                        "AwsIamAccessKey": {
                            "AccessKeyId": "ABC9ONWNS3155VIEJC8U",
                            "AccountId": "123456789012",
                            "PrincipalId": "ABCDEFGH0TOGJSGNQKI0:john.doe",
                            "PrincipalType": "AssumedRole",
                            "SessionContext": {
                                "Attributes": {"CreationDate": "2024-05-24T22:32:38Z", "MfaAuthenticated": False},
                                "SessionIssuer": {
                                    "AccountId": "123456789012",
                                    "Arn": "arn:aws:iam::123456789012:user/tester",
                                    "PrincipalId": "ABCDEFGH0TOGJSGNQKI0",
                                    "Type": "Role",
                                    "UserName": "user_ab21cde50f",
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
            "Title": "Suspicious activity detected accessing private decoy IAM role arn:aws:iam::123456789012:role/Dummy-Test-InfoRole-ab21cde50f",
            "Types": ["Unusual Behaviors"],
            "UpdatedAt": "2024-05-24 13:17:15.000000000",
            "Workflow": {"Status": "NEW"},
            "WorkflowState": "NEW",
            "p_any_actor_ids": [],
            "p_any_aws_account_ids": [],
            "p_any_aws_arns": [],
            "p_any_trace_ids": [],
            "p_any_usernames": [],
            "p_event_time": "2024-05-24 22:34:07.000000000",
            "p_log_type": "AWS.SecurityFindingFormat",
            "p_parse_time": "2024-05-24 22:35:04.272574202",
            "p_row_id": "zjj8nmnw9f90uulxfa3bmen8rv5stlcx",
            "p_schema_version": 0,
            "p_source_id": "bb4e16c5-43dd-450c-9227-39f0d152659c",
            "p_source_label": "AWS Security Hub",
            "p_udm": {},
        },
    ),
    RuleTest(
        name="IAM-Decoy-Not-Assumed",
        expected_result=False,
        log={
            "Action": {
                "ActionType": "AWS_API_CALL",
                "AwsApiCallAction": {
                    "Api": "ListRoles",
                    "CallerType": "remoteIp",
                    "DomainDetails": {},
                    "RemoteIpDetails": {
                        "City": {},
                        "Country": {},
                        "GeoLocation": {},
                        "IpAddressV4": "99.6.134.57",
                        "Organization": {},
                    },
                    "ServiceName": "sts.amazonaws.com",
                },
                "DnsRequestAction": {},
                "NetworkConnectionAction": {"LocalPortDetails": {}, "RemotePortDetails": {}},
                "PortProbeAction": {},
            },
            "AwsAccountId": "123456789012",
            "CompanyName": "Custom",
            "CreatedAt": "2024-05-24 13:17:15.000000000",
            "Description": "Private decoy IAM role arn:aws:iam::123456789012:role/Dummy-Test-InfoRole-ab21cde50f was not accessed by arn:aws:iam::123456789012:user/tester. This IAM role has been provisioned to monitor and generate security events when accessed and can be an indicator of unintended or unauthorized access to your AWS Account.",
            "FindingProviderFields": {"Severity": {"Label": "HIGH", "Normalized": 70}, "Types": ["Unusual Behaviors"]},
            "GeneratorId": "sts.amazonaws.com",
            "Id": "1abc2de3-69ea-4e15-91c6-27eb4a07bd21",
            "ProcessedAt": "2024-05-24T13:17:21.469Z",
            "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
            "ProductFields": {
                "Custom/DecoyDetector/apiResult": "SUCCESS",
                "Custom/DecoyDetector/requestID": "ab1cd123-1986-4c45-8546-fdb1776e23b0",
                "Custom/DecoyDetector/userAgent": "AWS Signin, aws-internal/3 aws-sdk-java/1.12.720 Linux/5.10.215-181.850.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/17.0.11+10-LTS java/17.0.11 kotlin/1.3.72 vendor/Amazon.com_Inc. cfg/retry-mode/standard cfg/auth-source#unknown",
                "aws/securityhub/CompanyName": "Personal",
                "aws/securityhub/FindingId": "arn:aws:service:region:123456789012:resource/12345ab9-436d-4d59-ac58-ed6b3127e440",
                "aws/securityhub/ProductName": "Default",
            },
            "ProductName": "DecoyDetector",
            "RecordState": "ACTIVE",
            "Region": "us-east-1",
            "Resources": [
                {
                    "Id": "arn:aws:iam::123456789012:role/Dummy-Test-InfoRole-ab21cde50f",
                    "Partition": "aws",
                    "Region": "us-east-1",
                    "ResourceRole": "Target",
                    "Type": "AwsIamRole",
                },
                {
                    "Details": {
                        "AwsIamAccessKey": {
                            "AccessKeyId": "ABC9ONWNS3155VIEJC8U",
                            "AccountId": "123456789012",
                            "PrincipalId": "ABCDEFGH0TOGJSGNQKI0:john.doe",
                            "PrincipalType": "AssumedRole",
                            "SessionContext": {
                                "Attributes": {"CreationDate": "2024-05-24T22:32:38Z", "MfaAuthenticated": False},
                                "SessionIssuer": {
                                    "AccountId": "123456789012",
                                    "Arn": "arn:aws:iam::123456789012:user/tester",
                                    "PrincipalId": "ABCDEFGH0TOGJSGNQKI0",
                                    "Type": "Role",
                                    "UserName": "user_ab21cde50f",
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
            "Title": "Non-Suspicious activity detected accessing private decoy IAM role arn:aws:iam::123456789012:role/Dummy-Test-InfoRole-ab21cde50f",
            "Types": ["Unusual Behaviors"],
            "UpdatedAt": "2024-05-24 13:17:15.000000000",
            "Workflow": {"Status": "NEW"},
            "WorkflowState": "NEW",
            "p_any_actor_ids": [],
            "p_any_aws_account_ids": [],
            "p_any_aws_arns": [],
            "p_any_trace_ids": [],
            "p_any_usernames": [],
            "p_event_time": "2024-05-24 22:34:07.000000000",
            "p_log_type": "AWS.SecurityFindingFormat",
            "p_parse_time": "2024-05-24 22:35:04.272574202",
            "p_row_id": "zjj8nmnw9f90uulxfa3bmen8rv5stlcx",
            "p_schema_version": 0,
            "p_source_id": "bb4e16c5-43dd-450c-9227-39f0d152659c",
            "p_source_label": "AWS Security Hub",
            "p_udm": {},
        },
    ),
]


@panther_managed
class DecoyIAMAssumed(Rule):
    id = "Decoy.IAM.Assumed-prototype"
    display_name = "Decoy IAM Assumed"
    enabled = False
    log_types = [LogType.AWS_SECURITY_FINDING_FORMAT]
    default_severity = Severity.HIGH
    default_description = "Actor assumed decoy IAM role"
    default_reference = "https://aws.amazon.com/blogs/security/how-to-detect-suspicious-activity-in-your-aws-account-by-using-private-decoy-resources/"
    inline_filters = [{"All": []}]
    tests = decoy_iam_assumed_tests

    def rule(self, event):
        # List of suspicious API events
        # NOTE: There may be more API events that's not listed
        suspicious_api_events = ["AssumeRole"]
        # Return True if the API value is in the list of suspicious API events
        if event["GeneratorId"] == "sts.amazonaws.com":
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
        return f"Suspicious activity detected accessing private decoy IAM role {secret}"
