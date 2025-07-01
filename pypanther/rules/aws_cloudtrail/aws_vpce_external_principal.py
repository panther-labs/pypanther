from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context, lookup_aws_account_name


@panther_managed
class AWSCloudTrailVPCEExternalPrincipal(Rule):
    id = "AWS.CloudTrail.VPCE.ExternalPrincipal-prototype"
    display_name = "External Principal Accessing AWS Resources Via VPC Endpoint"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = [
        "AWS",
        "CloudTrail",
        "VPCEndpoint",
        "Network Boundary Bridging",
        "Cloud Service Discovery",
        "Exfiltration Over Alternative Protocol",
    ]
    reports = {"MITRE ATT&CK": ["TA0005:T1599", "TA0007:T1526", "TA0010:T1048"]}
    default_severity = Severity.MEDIUM
    default_description = "This rule detects when a principal from one AWS account accesses resources in a different AWS account using a VPC Endpoint. While cross-account access may be expected in some cases, it could also indicate unauthorized lateral movement between AWS accounts.\n"
    default_runbook = "1. Identify the principal account and the accessed account from the alert context. 2. Verify if the cross-account access is expected and authorized:\n   - Check if the principal account is part of your organization\n   - Review IAM policies for the VPC Endpoint to confirm if cross-account access is intentional\n   - Check resource policies for the accessed service to confirm if the principal should have access\n3. If the access is unexpected:\n   - Review the API calls made by the principal\n   - Check the VPC Endpoint configuration for potential misconfiguration\n   - Consider restricting VPC Endpoint access to prevent unauthorized cross-account access\n   - Investigate for additional signs of unauthorized access\n4. Document findings and take appropriate remediation steps based on investigation.\n"
    default_reference = "https://www.wiz.io/blog/aws-vpc-endpoint-cloudtrail"

    def rule(self, event):
        # Check if this is a VPC Endpoint network activity event
        if event.get("eventType") != "AwsVpceEvent" or event.get("eventCategory") != "NetworkActivity":
            return False
        # Look for external principal pattern (limited userIdentity field)
        user_identity = event.get("userIdentity", {})
        # If it's an AWS account type without full identity details, it could be an external principal
        if (
            user_identity.get("type") == "AWSAccount"
            and "arn" not in user_identity
            and ("principalId" in user_identity)
        ):
            # Get the account ID from the event and compare with the principal's account
            event_account = event.get("recipientAccountId")
            principal_account = user_identity.get("accountId")
            # If the accounts don't match, it's an external principal
            if event_account and principal_account and (event_account != principal_account):
                return True
        return False

    def title(self, event):
        # Use UDM actor_user which leverages the get_actor_user helper function
        # This properly handles various identity types including AssumedRole, Root, etc.
        actor_user = event.udm("actor_user")
        principal_account = event.deep_get("userIdentity", "accountId", default="unknown")
        event_account = event.get("recipientAccountId", "unknown")
        return f"External Principal [{actor_user}] from account [{principal_account}] accessing resources in account [{event_account}]"

    def alert_context(self, event):
        principal_account = event.deep_get("userIdentity", "accountId", default="")
        event_account = event.get("recipientAccountId", "")
        context = aws_rule_context(event)
        context.update(
            {
                "event_account": event_account,
                "event_account_name": lookup_aws_account_name(event_account) if event_account else "unknown",
                "principal_account": principal_account,
                "principal_account_name": lookup_aws_account_name(principal_account)
                if principal_account
                else "unknown",
                "principal_id": event.deep_get("userIdentity", "principalId", default="unknown"),
                "source_ip": event.get("sourceIPAddress", "unknown"),
                "event_source": event.get("eventSource", "unknown"),
                "api_call": event.get("eventName", "unknown"),
                "resources": event.get("resources", []),
                "actor_user": event.udm("actor_user"),
            },
        )
        return context

    tests = [
        RuleTest(
            name="External Principal Access",
            expected_result=True,
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
                    "type": "AWSAccount",
                    "accountId": "111111111111",
                    "principalId": "AROAEXAMPLE:session-name",
                },
                "recipientAccountId": "222222222222",
                "requestParameters": {"bucketName": "example-bucket", "key": "sensitive-file.txt"},
                "responseElements": None,
                "vpcEndpointId": "vpce-EXAMPLE08c1b6b9b7",
                "vpcEndpointAccountId": "222222222222",
            },
        ),
        RuleTest(
            name="Same Account Access",
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
                    "type": "AWSAccount",
                    "accountId": "222222222222",
                    "principalId": "AROAEXAMPLE:session-name",
                },
                "recipientAccountId": "222222222222",
                "requestParameters": {"bucketName": "example-bucket", "key": "sensitive-file.txt"},
                "responseElements": None,
                "vpcEndpointId": "vpce-EXAMPLE08c1b6b9b7",
                "vpcEndpointAccountId": "222222222222",
            },
        ),
        RuleTest(
            name="Non-VPC Event",
            expected_result=False,
            log={
                "eventVersion": "1.08",
                "eventCategory": "Management",
                "eventType": "AwsApiCall",
                "eventTime": "2023-03-01T00:00:00Z",
                "awsRegion": "us-east-1",
                "eventSource": "s3.amazonaws.com",
                "eventName": "GetObject",
                "sourceIPAddress": "10.0.0.1",
                "userIdentity": {
                    "type": "AWSAccount",
                    "accountId": "111111111111",
                    "principalId": "AROAEXAMPLE:session-name",
                },
                "recipientAccountId": "222222222222",
                "requestParameters": {"bucketName": "example-bucket", "key": "sensitive-file.txt"},
                "responseElements": None,
            },
        ),
    ]
