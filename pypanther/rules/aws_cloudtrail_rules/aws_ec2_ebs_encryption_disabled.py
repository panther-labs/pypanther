from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context
from pypanther.log_types import LogType

awsec2_ebs_encryption_disabled_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="DisableEbsEncryptionByDefault Event",
        ExpectedResult=True,
        Log={
            "awsRegion": "us-east-1",
            "eventName": "DisableEbsEncryptionByDefault",
            "eventSource": "ec2.amazonaws.com",
            "recipientAccountId": "123456789",
            "sourceIPAddress": "1.2.3.4",
            "userAgent": "Chrome Browser",
        },
    ),
    PantherRuleTest(
        Name="Non Matching Event",
        ExpectedResult=False,
        Log={
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


class AWSEC2EBSEncryptionDisabled(PantherRule):
    Description = "Identifies disabling of default EBS encryption. Disabling default encryption does not change the encryption status of existing volumes. "
    DisplayName = "AWS EC2 EBS Encryption Disabled"
    Reports = {"MITRE ATT&CK": ["TA0040:T1486", "TA0040:T1565"]}
    Runbook = (
        "Verify this action was intended and if any EBS volumes were created after the change."
    )
    Reference = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"
    Severity = PantherSeverity.Medium
    LogTypes = [LogType.AWS_CloudTrail]
    RuleID = "AWS.EC2.EBS.Encryption.Disabled-prototype"
    Tests = awsec2_ebs_encryption_disabled_tests

    def rule(self, event):
        return (
            event.get("eventSource") == "ec2.amazonaws.com"
            and event.get("eventName") == "DisableEbsEncryptionByDefault"
        )

    def title(self, event):
        return f"EC2 EBS Default Encryption was disabled in [{event.get('recipientAccountId')}] - [{event.get('awsRegion')}]"

    def alert_context(self, event):
        return aws_rule_context(event)
