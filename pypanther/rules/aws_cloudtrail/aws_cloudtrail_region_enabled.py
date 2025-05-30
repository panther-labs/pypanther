from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSCloudTrailEnableRegion(Rule):
    display_name = "AWS Cloudtrail Region Enabled"
    id = "AWS.CloudTrail.EnableRegion-prototype"
    default_severity = Severity.MEDIUM
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "CloudTrail", "Region"]
    reports = {"MITRE ATT&CK": ["TA0005:T1535"]}
    default_description = "Threat actors who successfully compromise a victim's AWS account, whether through stolen credentials,  exposed access keys, exploited IAM misconfigurations, vulnerabilities in third-party applications,  or the absence of Multi-Factor Authentication (MFA), can exploit unused regions as safe zones  for malicious activities. These regions are often overlooked in monitoring and security setups,  making them an attractive target for attackers to operate undetected.\n"
    default_runbook = "Validate whether enabling the new region was authorized.   Revoke user privileges, review the newly enabled region for malicious activity, and disable the region.\n"
    default_reference = "https://permiso.io/blog/how-threat-actors-leverage-unsupported-cloud-regions"

    def rule(self, event):
        return event.get("eventName") == "EnableRegion"

    def title(self, event):
        return f"AWS CloudTrail region [{event.deep_get('requestParameters', 'RegionName')}] enabled by user [{event.udm('actor_user')}]"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="EnableRegion",
            expected_result=True,
            log={
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "EXAMPLE",
                    "arn": "arn:aws:iam::123456789012:user/Alice",
                    "accountId": "123456789012",
                    "accessKeyId": "EXAMPLEKEY",
                    "userName": "Alice",
                },
                "eventTime": "2023-10-01T12:34:56Z",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventName": "EnableRegion",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.0.2.0",
                "userAgent": "aws-sdk-go/1.15.12 (go1.12.6; linux; amd64)",
                "requestParameters": {"RegionName": "us-west-2"},
                "responseElements": None,
                "additionalEventData": {
                    "SignatureVersion": "SigV4",
                    "CipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "bytesTransferredIn": 0,
                    "bytesTransferredOut": 0,
                },
                "requestID": "EXAMPLE123456789",
                "eventID": "EXAMPLE-1234-5678-9012-EXAMPLE",
                "readOnly": False,
                "resources": [],
                "eventType": "AwsApiCall",
                "managementEvent": False,
                "recipientAccountId": "123456789012",
                "sharedEventID": "EXAMPLE-1234-5678-9012-EXAMPLE",
                "vpcEndpointId": "vpce-1a2b3c4d",
            },
        ),
        RuleTest(
            name="Other Event",
            expected_result=False,
            log={
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "EXAMPLE",
                    "arn": "arn:aws:iam::123456789012:user/Bob",
                    "accountId": "123456789012",
                    "accessKeyId": "EXAMPLEKEY",
                    "userName": "Bob",
                },
                "eventTime": "2023-10-01T12:34:56Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "ListBucket",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.0.2.0",
                "userAgent": "aws-sdk-go/1.15.12 (go1.12.6; linux; amd64)",
                "requestParameters": {"bucketName": "example-bucket"},
                "responseElements": None,
                "additionalEventData": {
                    "SignatureVersion": "SigV4",
                    "CipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "bytesTransferredIn": 0,
                    "bytesTransferredOut": 0,
                },
                "requestID": "EXAMPLE123456789",
                "eventID": "EXAMPLE-1234-5678-9012-EXAMPLE",
                "readOnly": True,
                "resources": [{"type": "AWS::S3::Bucket", "ARN": "arn:aws:s3:::example-bucket"}],
                "eventType": "AwsApiCall",
                "managementEvent": False,
                "recipientAccountId": "123456789012",
                "sharedEventID": "EXAMPLE-1234-5678-9012-EXAMPLE",
                "vpcEndpointId": "vpce-1a2b3c4d",
            },
        ),
    ]
