from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context, lookup_aws_account_name


@panther_managed
class AWSCloudTrailVPCEAccessDenied(Rule):
    id = "AWS.CloudTrail.VPCE.AccessDenied-prototype"
    display_name = "VPC Endpoint Access Denied"
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.MEDIUM
    tags = [
        "AWS",
        "VPC",
        "CloudTrail",
        "Network Boundary Bridging",
        "Defense Evasion",
        "Lateral Movement",
        "Impair Defenses",
    ]
    reports = {"MITRE ATT&CK": ["TA0005:T1599", "TA0007:T1526"]}
    default_description = "Detects when access is denied due to VPC Endpoint policies, which could indicate attempted unauthorized access to AWS resources."
    default_runbook = "1. Identify the principal (user/role) and source IP that was denied access 2. Determine if this is expected behavior based on your VPC endpoint policies 3. Check if there are multiple failed attempts from the same principal/IP 4. If unexpected, investigate why the principal is attempting to access resources through the VPC endpoint 5. Consider updating your VPC endpoint policies if necessary 6. Document findings and take appropriate remediation steps based on investigation\n"
    default_reference = "https://www.wiz.io/blog/aws-vpc-endpoint-cloudtrail"
    summary_attributes = [
        "errorCode",
        "errorMessage",
        "sourceIPAddress",
        "eventSource",
        "eventName",
        "userIdentity.principalId",
    ]

    def rule(self, event):
        # Check if this is a VPC Endpoint network activity event
        if event.get("eventType") != "AwsVpceEvent" or event.get("eventCategory") != "NetworkActivity":
            return False
        # Look for access denied errors
        if event.get("errorCode") == "VpceAccessDenied":
            return True
        return False

    def title(self, event):
        actor_user = event.udm("actor_user")
        source_ip = event.get("sourceIPAddress", "unknown")
        service = event.get("eventSource", "unknown").split(".")[0]
        return f"VPC Endpoint Access Denied for [{actor_user}] from [{source_ip}] to [{service}]"

    def alert_context(self, event):
        account_id = event.deep_get("userIdentity", "accountId", default="")
        account_name = lookup_aws_account_name(account_id) if account_id else "unknown"
        context = aws_rule_context(event)
        context.update(
            {
                "account_id": account_id,
                "account_name": account_name,
                "principal_id": event.deep_get("userIdentity", "principalId", default="unknown"),
                "source_ip": event.get("sourceIPAddress", "unknown"),
                "event_source": event.get("eventSource", "unknown"),
                "api_call": event.get("eventName", "unknown"),
                "error_message": event.get("errorMessage", ""),
                "resources": event.get("resources", []),
                "actor_user": event.udm("actor_user"),
            },
        )
        return context

    tests = [
        RuleTest(
            name="VPC Endpoint Access Denied",
            expected_result=True,
            log={
                "eventVersion": "1.08",
                "eventCategory": "NetworkActivity",
                "eventType": "AwsVpceEvent",
                "errorCode": "VpceAccessDenied",
                "errorMessage": "The request was denied due to a VPC endpoint policy",
                "eventTime": "2023-03-01T00:00:00Z",
                "awsRegion": "us-east-1",
                "eventSource": "s3.amazonaws.com",
                "eventName": "GetObject",
                "sourceIPAddress": "10.0.0.1",
                "userIdentity": {
                    "type": "AWSAccount",
                    "principalId": "AROAEXAMPLE:session-name",
                    "accountId": "111111111111",
                },
                "recipientAccountId": "222222222222",
                "requestParameters": {"bucketName": "example-bucket", "key": "sensitive-file.txt"},
                "responseElements": None,
                "vpcEndpointId": "vpce-EXAMPLE08c1b6b9b7",
                "vpcEndpointAccountId": "222222222222",
            },
        ),
        RuleTest(
            name="Not VPC Endpoint Event",
            expected_result=False,
            log={
                "eventVersion": "1.08",
                "eventCategory": "Management",
                "eventType": "AwsApiCall",
                "errorCode": "AccessDenied",
                "errorMessage": "Access Denied",
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
                "recipientAccountId": "222222222222",
                "requestParameters": {"bucketName": "example-bucket", "key": "sensitive-file.txt"},
                "responseElements": None,
            },
        ),
        RuleTest(
            name="VPC Endpoint Event Without Error",
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
                "recipientAccountId": "222222222222",
                "requestParameters": {"bucketName": "example-bucket", "key": "sensitive-file.txt"},
                "responseElements": None,
            },
        ),
    ]
