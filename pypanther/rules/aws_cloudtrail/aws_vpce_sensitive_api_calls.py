from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context, lookup_aws_account_name


@panther_managed
class AWSCloudTrailVPCESensitiveAPICalls(Rule):
    id = "AWS.CloudTrail.VPCE.SensitiveAPICalls-prototype"
    display_name = "Sensitive API Calls Via VPC Endpoint"
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.MEDIUM
    tags = [
        "AWS",
        "VPC",
        "CloudTrail",
        "Network Boundary Bridging",
        "Cloud Service Discovery",
        "Account Manipulation",
        "Impair Defenses",
    ]
    reports = {"MITRE ATT&CK": ["TA0007:T1526", "TA0003:T1098", "TA0005:T1562", "TA0005:T1599"]}
    default_description = "Detects sensitive or unusual API calls that might indicate lateral movement, reconnaissance, or other malicious activities through VPC Endpoints. Only available for CloudTrail, EC2, KMS, S3, and Secrets Manager services."
    default_runbook = "1. Identify the principal making the sensitive API call and the specific service affected 2. Determine if this action is expected from this principal 3. Check if the API call is one that typically requires additional scrutiny (e.g., logging configuration changes) 4. Investigate whether the VPC Endpoint is configured to properly restrict access 5. Review additional API calls from the same principal for suspicious patterns 6. If unexpected activity is confirmed, consider temporarily restricting the principal's access 7. Document findings and take appropriate remediation steps based on investigation\n"
    default_reference = "https://www.wiz.io/blog/aws-vpc-endpoint-cloudtrail"
    summary_attributes = [
        "userIdentity.principalId",
        "userIdentity.accountId",
        "sourceIPAddress",
        "eventSource",
        "eventName",
    ]
    # Define sensitive API calls to monitor as a constant
    SENSITIVE_APIS = {
        "ec2.amazonaws.com": [
            "DescribeInstances",
            "DescribeNetworkInterfaces",
            "CreateKeyPair",
            "ImportKeyPair",
            "RunInstances",
        ],
        "kms.amazonaws.com": ["Decrypt", "GenerateDataKey", "CreateKey", "ScheduleKeyDeletion"],
        "secretsmanager.amazonaws.com": ["GetSecretValue", "CreateSecret", "PutSecretValue", "DeleteSecret"],
        "s3.amazonaws.com": ["ListAllMyBuckets", "DeleteBucketPolicy", "PutBucketPolicy"],
        "cloudtrail.amazonaws.com": ["StopLogging", "DeleteTrail", "UpdateTrail"],
    }

    def rule(self, event):
        # Check if this is a VPC Endpoint network activity event
        if event.get("eventType") != "AwsVpceEvent" or event.get("eventCategory") != "NetworkActivity":
            return False
        event_source = event.get("eventSource")
        event_name = event.get("eventName")
        if event_source in self.SENSITIVE_APIS and event_name in self.SENSITIVE_APIS[event_source]:
            return True
        return False

    def title(self, event):
        # Use UDM actor_user which leverages the get_actor_user helper function
        # This properly handles various identity types including AssumedRole, Root, etc.
        actor_user = event.udm("actor_user")
        api_name = event.get("eventName", "unknown")
        service = event.get("eventSource", "unknown").split(".")[0]
        return f"Sensitive AWS API [{api_name}] called via VPC Endpoint by [{actor_user}] to service [{service}]"

    def alert_context(self, event):
        account_id = event.deep_get("userIdentity", "accountId", default="")
        context = aws_rule_context(event)
        context.update(
            {
                "account_id": account_id,
                "account_name": lookup_aws_account_name(account_id) if account_id else "unknown",
                "principal_id": event.deep_get("userIdentity", "principalId", default="unknown"),
                "principal_type": event.deep_get("userIdentity", "type", default="unknown"),
                "actor_user": event.udm("actor_user"),
                "source_ip": event.get("sourceIPAddress", "unknown"),
                "event_source": event.get("eventSource", "unknown"),
                "api_call": event.get("eventName", "unknown"),
                "resources": event.get("resources", []),
                "request_parameters": event.get("requestParameters", {}),
            },
        )
        return context

    tests = [
        RuleTest(
            name="CloudTrail API Call Via VPC Endpoint",
            expected_result=True,
            log={
                "eventVersion": "1.08",
                "eventCategory": "NetworkActivity",
                "eventType": "AwsVpceEvent",
                "eventTime": "2023-03-01T00:00:00Z",
                "awsRegion": "us-east-1",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventName": "UpdateTrail",
                "sourceIPAddress": "10.0.0.1",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AROAEXAMPLE:session-name",
                    "accountId": "111111111111",
                },
                "requestParameters": {"name": "management-events", "isMultiRegionTrail": False},
                "responseElements": None,
                "vpcEndpointId": "vpce-1234abcd",
                "vpcEndpointAccountId": "111111111111",
                "recipientAccountId": "111111111111",
            },
        ),
        RuleTest(
            name="Regular S3 API Call (Not Sensitive)",
            expected_result=False,
            log={
                "eventVersion": "1.08",
                "eventCategory": "NetworkActivity",
                "eventType": "AwsVpceEvent",
                "eventTime": "2023-03-01T00:00:00Z",
                "awsRegion": "us-east-1",
                "eventSource": "s3.amazonaws.com",
                "eventName": "GetObject",
                "sourceIPAddress": "10.0.0.1",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AROAEXAMPLE:session-name",
                    "accountId": "111111111111",
                },
                "requestParameters": {"bucketName": "example-bucket", "key": "example-file.txt"},
                "responseElements": None,
                "vpcEndpointId": "vpce-1234abcd",
                "vpcEndpointAccountId": "111111111111",
                "recipientAccountId": "111111111111",
            },
        ),
        RuleTest(
            name="API Call Without VPC Endpoint",
            expected_result=False,
            log={
                "eventVersion": "1.08",
                "eventCategory": "Management",
                "eventType": "AwsApiCall",
                "eventTime": "2023-03-01T00:00:00Z",
                "awsRegion": "us-east-1",
                "eventSource": "s3.amazonaws.com",
                "eventName": "ListAllMyBuckets",
                "sourceIPAddress": "203.0.113.1",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AROAEXAMPLE:session-name",
                    "accountId": "111111111111",
                },
                "requestParameters": {},
                "responseElements": None,
            },
        ),
    ]
