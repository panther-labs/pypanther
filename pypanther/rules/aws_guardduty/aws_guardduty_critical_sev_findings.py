from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_guardduty_context


@panther_managed
class AWSGuardDutyCriticalSeverityFinding(Rule):
    id = "AWS.GuardDuty.CriticalSeverityFinding-prototype"
    display_name = "AWS GuardDuty Critical Severity Finding"
    log_types = [LogType.AWS_GUARDDUTY]
    tags = ["AWS"]
    default_severity = Severity.CRITICAL
    dedup_period_minutes = 15
    default_description = "A critical-severity GuardDuty finding has been identified.\n"
    default_runbook = "Search related logs to understand the root cause of the activity. Search the Panther Summary Attribute type value in https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html for additional details.\n"
    default_reference = (
        "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html#guardduty_findings-severity"
    )
    summary_attributes = ["severity", "type", "title", "p_any_domain_names", "p_any_aws_arns", "p_any_aws_account_ids"]

    def rule(self, event):
        if event.deep_get("service", "additionalInfo", "sample"):
            # in case of sample data
            # https://docs.aws.amazon.com/guardduty/latest/ug/sample_findings.html
            return False
        return 9.0 <= float(event.get("severity", 0)) <= 10.0

    def title(self, event):
        return event.get("title")

    def alert_context(self, event):
        return aws_guardduty_context(event)

    tests = [
        RuleTest(
            name="Critical Sev Finding",
            expected_result=True,
            log={
                "accountId": "123456789012",
                "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/111111bbbbbbbbbb5555555551111111/finding/8c258d654378414b9bc26f61a93eb816",
                "createdAt": "2025-02-25 20:40:06.721",
                "description": "A sequence of actions involving 4 signals indicating a possible credential compromise was observed for IAMUser/john_doe with principalId AIDA3UBBJ2K3TVEXAMPLE in account 111122223333\nbetween eventFirstSeen and eventLastSeen with the following behaviors:\n  - 5 MITRE ATT&CK tactics observed: Persistence, Privilege Escalation, Defense Evasion, Discovery, Initial Access\n  - 5 MITRE ATT&CK techniques observed: T1562.008 - Impair Defenses: Disable or Modify Cloud Logs, T1098.003 - Account Manipulation: Additional Cloud Roles, T1078.004 - Valid Accounts: Cloud Accounts, T1087.004 - Account Discovery: Cloud Account, T1098 - Account Manipulation\n  - Connected from a known Tor Exit Node: 10.0.0.1\n  - 4 sensitive APIs called: cloudtrail:DeleteTrail, iam:AttachRolePolicy, iam:CreateRole, iam:ListUsers\n",
                "id": "8c258d654378414b9bc26f61a93eb816",
                "partition": "aws",
                "region": "us-east-1",
                "resource": {"resourceType": "AttackSequence"},
                "schemaVersion": "2.0",
                "service": {
                    "additionalInfo": {},
                    "archived": False,
                    "count": 1,
                    "detectorId": "111111bbbbbbbbbb5555555551111111",
                    "eventFirstSeen": "2025-02-25 20:40:06.000000000",
                    "eventLastSeen": "2025-02-25 20:40:06.000000000",
                    "featureName": "Correlation",
                    "resourceRole": "TARGET",
                    "serviceName": "guardduty",
                },
                "severity": 9,
                "title": "Potential credential compromise of IAMUser/john_doe indicated by a sequence of actions.",
                "type": "AttackSequence:IAM/CompromisedCredentials",
                "updatedAt": "2025-02-25 20:40:06.721",
            },
        ),
        RuleTest(
            name="Critical Sev Finding As Sample Data",
            expected_result=False,
            log={
                "accountId": "123456789012",
                "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/111111bbbbbbbbbb5555555551111111/finding/b174b38d16e34da0a4c66012083bd8f7",
                "createdAt": "2025-02-25 20:40:06.765",
                "description": "A sequence of actions involving 14 signals indicating a possible credential compromise one or more S3 bucket(s) was observed for IAMUser/john_doe with principalId AIDA3UBBJ2K3TVEXAMPLE in account 111122223333\nbetween eventFirstSeen and eventLastSeen with the following behaviors:\n  - 5 MITRE ATT&CK tactics observed: Exfiltration, Impact, Persistence, Defense Evasion, Discovery\n  - 5 MITRE ATT&CK techniques observed: T1526 - Cloud Service Discovery, T1098 - Account Manipulation, T1078.004 - Valid Accounts: Cloud Accounts, T1485 - Data Destruction, T1530 - Data from Cloud Storage\n  - Connected from a known Tor Exit Node: 10.0.0.1\n  - 7 sensitive APIs called: s3:DeleteObject, s3:GetObject, s3:PutBucketPublicAccessBlock, cloudtrail:DeleteTrail, iam:AttachUserPolicy, s3:ListObjects, s3:ListBuckets\n",
                "id": "b174b38d16e34da0a4c66012083bd8f7",
                "partition": "aws",
                "region": "us-east-1",
                "resource": {"resourceType": "AttackSequence"},
                "schemaVersion": "2.0",
                "service": {
                    "additionalInfo": {"sample": True, "type": "default", "value": '{"sample":true}'},
                    "archived": False,
                    "count": 1,
                    "detectorId": "111111bbbbbbbbbb5555555551111111",
                    "eventFirstSeen": "2025-02-25 20:40:06.000000000",
                    "eventLastSeen": "2025-02-25 20:40:06.000000000",
                    "featureName": "Correlation",
                    "resourceRole": "TARGET",
                    "serviceName": "guardduty",
                },
                "severity": 9,
                "title": "Potential data compromise of one or more S3 buckets involving a sequence of actions associated with IAMUser/john_doe.",
                "type": "AttackSequence:S3/CompromisedData",
                "updatedAt": "2025-02-25 20:40:06.765",
            },
        ),
    ]
