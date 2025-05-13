import ipaddress

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context, lookup_aws_account_name


@panther_managed
class AWSCloudTrailVPCES3ExternalIP(Rule):
    id = "AWS.CloudTrail.VPCE.S3ExternalIP-prototype"
    display_name = "S3 Access Via VPC Endpoint From External IP"
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.MEDIUM
    tags = [
        "AWS",
        "VPC",
        "S3",
        "Data Exfiltration",
        "CloudTrail",
        "Network Boundary Bridging",
        "Exfiltration Over Alternative Protocol",
    ]
    default_description = "Detects S3 data access through VPC endpoints from external/public IP addresses, which could indicate data exfiltration attempts.\n\nThis rule can be customized with the following overrides:\n- S3_DATA_ACCESS_OPERATIONS: List of S3 operations to monitor\n"
    default_runbook = "1. Identify the principal and the specific S3 objects being accessed\n2. Verify if the external IP address belongs to a legitimate service or entity\n3. Check if the access pattern is expected for this user/role\n4. Review the contents of the S3 objects to determine sensitivity\n5. If unauthorized, determine how the principal obtained access credentials\n6. Revoke access immediately if determined to be malicious\n7. Consider implementing stricter bucket policies and VPC endpoint policies\n"
    default_reference = "https://www.wiz.io/blog/aws-vpc-endpoint-cloudtrail"
    summary_attributes = [
        "userIdentity.principalId",
        "sourceIPAddress",
        "eventSource",
        "eventName",
        "requestParameters",
        "resources",
    ]
    # Define S3 data access operations
    S3_DATA_ACCESS_OPERATIONS = [
        "GetObject",
        "GetObjectVersion",
        "GetObjectAcl",
        "GetObjectVersionAcl",
        "PutObject",
        "PutObjectAcl",
        "PutObjectVersionAcl",
        "CopyObject",
        "DeleteObject",
        "DeleteObjects",
        "DeleteObjectVersion",
    ]

    def rule(self, event):
        # Check if this is a VPC Endpoint network activity event for S3
        if (
            event.get("eventType") != "AwsVpceEvent"
            or event.get("eventCategory") != "NetworkActivity"
            or event.get("eventSource") != "s3.amazonaws.com"
        ):
            return False
        # Focus on data access operations
        if event.get("eventName") not in self.S3_DATA_ACCESS_OPERATIONS:
            return False
        # Check for external IP
        source_ip = event.get("sourceIPAddress", "")
        if not source_ip:
            return False
        try:
            ip_obj = ipaddress.ip_address(source_ip)
            if ip_obj.is_global:
                return True
        except ValueError:
            # If source_ip is not a valid IP address
            pass
        return False

    def title(self, event):
        # Use UDM actor_user which leverages the get_actor_user helper function
        actor_user = event.udm("actor_user")
        source_ip = event.get("sourceIPAddress", "unknown")
        bucket_name = event.deep_get("requestParameters", "bucketName", default="unknown")
        return (
            f"S3 Access via VPC Endpoint from External IP: [{actor_user}] from [{source_ip}] to bucket [{bucket_name}]"
        )

    def alert_context(self, event):
        account_id = event.deep_get("userIdentity", "accountId", default="")
        context = aws_rule_context(event)
        context.update(
            {
                "account_id": account_id,
                "account_name": lookup_aws_account_name(account_id) if account_id else "unknown",
                "principal_id": event.deep_get("userIdentity", "principalId", default="unknown"),
                "actor_user": event.udm("actor_user"),
                "source_ip": event.get("sourceIPAddress", "unknown"),
                "event_source": event.get("eventSource", "unknown"),
                "api_call": event.get("eventName", "unknown"),
                "resources": event.get("resources", []),
                "request_parameters": event.get("requestParameters", {}),
                "config": {"operations_monitored": self.S3_DATA_ACCESS_OPERATIONS},
            },
        )
        return context

    tests = [
        RuleTest(
            name="External IP Access",
            expected_result=True,
            log={
                "eventType": "AwsVpceEvent",
                "eventCategory": "NetworkActivity",
                "eventSource": "s3.amazonaws.com",
                "eventName": "GetObject",
                "userIdentity": {"type": "IAMUser", "principalId": "AIDAEXAMPLE", "accountId": "012345678901"},
                "sourceIPAddress": "8.8.8.8",
                "requestParameters": {"bucketName": "sensitive-data-bucket", "key": "confidential/file.pdf"},
                "resources": [
                    {"type": "AWS::S3::Object", "ARN": "arn:aws:s3:::sensitive-data-bucket/confidential/file.pdf"},
                ],
                "eventTime": "2023-01-01T12:00:00Z",
                "vpcEndpointId": "vpce-EXAMPLE08c1b6b9b7",
                "vpcEndpointAccountId": "012345678901",
                "recipientAccountId": "012345678901",
            },
        ),
        RuleTest(
            name="Internal IP Access",
            expected_result=False,
            log={
                "eventType": "AwsVpceEvent",
                "eventCategory": "NetworkActivity",
                "eventSource": "s3.amazonaws.com",
                "eventName": "GetObject",
                "userIdentity": {"type": "IAMUser", "principalId": "AIDAEXAMPLE", "accountId": "012345678901"},
                "sourceIPAddress": "10.0.0.1",
                "requestParameters": {"bucketName": "sensitive-data-bucket", "key": "confidential/file.pdf"},
                "resources": [
                    {"type": "AWS::S3::Object", "ARN": "arn:aws:s3:::sensitive-data-bucket/confidential/file.pdf"},
                ],
                "eventTime": "2023-01-01T12:00:00Z",
                "vpcEndpointId": "vpce-EXAMPLE08c1b6b9b7",
                "vpcEndpointAccountId": "012345678901",
                "recipientAccountId": "012345678901",
            },
        ),
        RuleTest(
            name="Not S3 Service",
            expected_result=False,
            log={
                "eventType": "AwsVpceEvent",
                "eventCategory": "NetworkActivity",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "DescribeInstances",
                "userIdentity": {"type": "IAMUser", "principalId": "AIDAEXAMPLE", "accountId": "012345678901"},
                "sourceIPAddress": "8.8.8.8",
            },
        ),
    ]
