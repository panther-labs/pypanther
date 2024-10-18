from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSEC2EBSEncryptionDisabled(Rule):
    default_description = "Identifies disabling of default EBS encryption. Disabling default encryption does not change the encryption status of existing volumes. "
    display_name = "AWS EC2 EBS Encryption Disabled"
    reports = {"MITRE ATT&CK": ["TA0040:T1486", "TA0040:T1565"]}
    default_runbook = "Verify this action was intended and if any EBS volumes were created after the change."
    default_reference = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"
    default_severity = Severity.MEDIUM
    log_types = [LogType.AWS_CLOUDTRAIL]
    id = "AWS.EC2.EBS.Encryption.Disabled-prototype"

    def rule(self, event):
        return (
            event.get("eventSource") == "ec2.amazonaws.com"
            and event.get("eventName") == "DisableEbsEncryptionByDefault"
        )

    def title(self, event):
        return f"EC2 EBS Default Encryption was disabled in [{event.get('recipientAccountId')}] - [{event.get('awsRegion')}]"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="DisableEbsEncryptionByDefault Event",
            expected_result=True,
            log={
                "awsRegion": "us-east-1",
                "eventName": "DisableEbsEncryptionByDefault",
                "eventSource": "ec2.amazonaws.com",
                "recipientAccountId": "123456789",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "Chrome Browser",
            },
        ),
        RuleTest(
            name="Non Matching Event",
            expected_result=False,
            log={
                "awsRegion": "ap-northeast-1",
                "eventName": "DescribeInstanceStatus",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2022-09-25 16:16:37",
                "eventType": "AwsApiCall",
                "readOnly": True,
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "Datadog",
            },
        ),
    ]
