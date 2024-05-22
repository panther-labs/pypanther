from typing import List

from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_base_helpers import aws_rule_context, deep_get

a_w_s_snapshot_backup_exfiltration_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Modified Snapshot Attribute",
        ExpectedResult=True,
        Log={
            "awsRegion": "us-east-1",
            "eventCategory": "Management",
            "eventName": "ModifySnapshotAttribute",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2022-09-29 22:28:40",
            "eventType": "AwsApiCall",
            "eventVersion": "1.08",
            "managementEvent": True,
            "readOnly": False,
            "recipientAccountId": "12345",
            "requestParameters": {
                "attributeType": "CREATE_VOLUME_PERMISSION",
                "createVolumePermission": {"add": {"items": [{"userId": "54321"}]}},
                "snapshotId": "snap-12345",
            },
            "responseElements": {"_return": True, "requestId": "12345"},
            "sessionCredentialFromConsole": True,
            "sourceIPAddress": "AWS Internal",
            "userAgent": "AWS Internal",
            "userIdentity": {
                "accessKeyId": "ABC123",
                "accountId": "12345",
                "arn": "arn:aws:sts::12345:assumed-role/aa/b",
                "principalId": "aa/b",
                "sessionContext": {
                    "attributes": {
                        "creationDate": "2022-09-29T22:22:46Z",
                        "mfaAuthenticated": "true",
                    },
                    "sessionIssuer": {
                        "accountId": "12345",
                        "arn": "arn:aws:iam::12345/aa/cc",
                        "principalId": "12345",
                        "type": "Role",
                        "userName": "cc",
                    },
                    "webIdFederationData": {},
                },
                "type": "AssumedRole",
            },
        },
    ),
    PantherRuleTest(
        Name="other ec2 event",
        ExpectedResult=False,
        Log={
            "awsRegion": "us-east-1",
            "eventCategory": "Management",
            "eventName": "TerminateInstances",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2022-09-29 22:27:40",
            "eventType": "AwsApiCall",
            "eventVersion": "1.08",
            "managementEvent": True,
            "readOnly": False,
            "recipientAccountId": "12345",
            "requestParameters": {"instancesSet": {"items": [{"instanceId": "i-12345"}]}},
            "responseElements": {
                "instancesSet": {
                    "items": [
                        {
                            "currentState": {"code": 32, "name": "shutting-down"},
                            "instanceId": "i-12345",
                            "previousState": {"code": 16, "name": "running"},
                        }
                    ]
                },
                "requestId": "12356",
            },
            "sessionCredentialFromConsole": True,
            "sourceIPAddress": "AWS Internal",
            "userAgent": "AWS Internal",
            "userIdentity": {
                "accessKeyId": "ABCD",
                "accountId": "12345",
                "arn": "arn:aws:sts::12345/aa",
                "principalId": "ABCD/12345",
                "sessionContext": {
                    "attributes": {
                        "creationDate": "2022-09-29T22:22:46Z",
                        "mfaAuthenticated": "true",
                    },
                    "sessionIssuer": {
                        "accountId": "927278427150",
                        "arn": "arn:aws:iam::ABCD/EFGH",
                        "principalId": "ABCD/12345",
                        "type": "Role",
                        "userName": "CCC",
                    },
                    "webIdFederationData": {},
                },
                "type": "AssumedRole",
            },
        },
    ),
]


class AWSSnapshotBackupExfiltration(PantherRule):
    Description = "Detects the modification of an EC2 snapshot's permissions to enable access from another account."
    DisplayName = "--DEPRECATED-- Snapshot Backup Exfiltration"
    Enabled = False
    Reports = {"MITRE ATT&CK": ["TA0010:T1537"]}
    Reference = (
        "https://docs.aws.amazon.com/prescriptive-guidance/latest/backup-recovery/ec2-backup.html"
    )
    Severity = Severity.Medium
    DedupPeriodMinutes = 60
    LogTypes = ["AWS.CloudTrail"]
    RuleID = "AWS.Snapshot.Backup.Exfiltration-prototype"
    Threshold = 1
    Tests = a_w_s_snapshot_backup_exfiltration_tests

    def rule(self, event):
        return (
            event.get("eventSource") == "ec2.amazonaws.com"
            and event.get("eventName") == "ModifySnapshotAttribute"
        )

    def title(self, event):
        return f"[{deep_get(event, 'userIdentity', 'arn')}] modified snapshot attributes for [{deep_get(event, 'requestParameters', 'snapshotId')}] in [{event.get('recipientAccountId')}] - [{event.get('awsRegion')}]."

    def alert_context(self, event):
        return aws_rule_context(event)
