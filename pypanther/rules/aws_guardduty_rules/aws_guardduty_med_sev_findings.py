from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_guardduty_context, deep_get
from pypanther.log_types import LogType

aws_guard_duty_medium_severity_finding_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Medium Sev Finding",
        ExpectedResult=True,
        Log={
            "schemaVersion": "2.0",
            "accountId": "123456789012",
            "region": "us-east-1",
            "id": "eeb88ab56556eb7771b266670dddee5a",
            "partition": "aws",
            "arn": "arn:aws:guardduty:us-west-2:123456789012:detector/111111bbbbbbbbbb5555555551111111/finding/90b82273685661b9318f078d0851fe9a",
            "type": "PrivilegeEscalation:IAMUser/AdministrativePermissions",
            "service": {
                "serviceName": "guardduty",
                "detectorId": "111111bbbbbbbbbb5555555551111111",
                "action": {
                    "actionType": "AWS_API_CALL",
                    "awsApiCallAction": {
                        "api": "PutRolePolicy",
                        "serviceName": "iam.amazonaws.com",
                        "callerType": "Domain",
                        "domainDetails": {"domain": "cloudformation.amazonaws.com"},
                        "affectedResources": {
                            "AWS::IAM::Role": "arn:aws:iam::123456789012:role/IAMRole"
                        },
                    },
                },
                "resourceRole": "TARGET",
                "additionalInfo": {},
                "evidence": None,
                "eventFirstSeen": "2020-02-14T17:59:17Z",
                "eventLastSeen": "2020-02-14T17:59:17Z",
                "archived": False,
                "count": 1,
            },
            "severity": 5,
            "createdAt": "2020-02-14T18:12:22.316Z",
            "updatedAt": "2020-02-14T18:12:22.316Z",
            "title": "Principal AssumedRole:IAMRole attempted to add a policy to themselves that is highly permissive.",
            "description": "Principal AssumedRole:IAMRole attempted to add a highly permissive policy to themselves.",
        },
    ),
    PantherRuleTest(
        Name="Medium Sev Finding As Sample Data",
        ExpectedResult=False,
        Log={
            "schemaVersion": "2.0",
            "accountId": "123456789012",
            "region": "us-east-1",
            "id": "eeb88ab56556eb7771b266670dddee5a",
            "partition": "aws",
            "arn": "arn:aws:guardduty:us-west-2:123456789012:detector/111111bbbbbbbbbb5555555551111111/finding/90b82273685661b9318f078d0851fe9a",
            "type": "PrivilegeEscalation:IAMUser/AdministrativePermissions",
            "service": {
                "serviceName": "guardduty",
                "detectorId": "111111bbbbbbbbbb5555555551111111",
                "action": {
                    "actionType": "AWS_API_CALL",
                    "awsApiCallAction": {
                        "api": "PutRolePolicy",
                        "serviceName": "iam.amazonaws.com",
                        "callerType": "Domain",
                        "domainDetails": {"domain": "cloudformation.amazonaws.com"},
                        "affectedResources": {
                            "AWS::IAM::Role": "arn:aws:iam::123456789012:role/IAMRole"
                        },
                    },
                },
                "resourceRole": "TARGET",
                "additionalInfo": {"sample": True},
                "evidence": None,
                "eventFirstSeen": "2020-02-14T17:59:17Z",
                "eventLastSeen": "2020-02-14T17:59:17Z",
                "archived": False,
                "count": 1,
            },
            "severity": 5,
            "createdAt": "2020-02-14T18:12:22.316Z",
            "updatedAt": "2020-02-14T18:12:22.316Z",
            "title": "Principal AssumedRole:IAMRole attempted to add a policy to themselves that is highly permissive.",
            "description": "Principal AssumedRole:IAMRole attempted to add a highly permissive policy to themselves.",
        },
    ),
]


class AWSGuardDutyMediumSeverityFinding(PantherRule):
    RuleID = "AWS.GuardDuty.MediumSeverityFinding-prototype"
    DisplayName = "AWS GuardDuty Medium Severity Finding"
    LogTypes = [LogType.AWS_GuardDuty]
    Tags = ["AWS"]
    Severity = PantherSeverity.Medium
    DedupPeriodMinutes = 480
    Description = "A medium-severity GuardDuty finding has been identified.\n"
    Runbook = "Search related logs to understand the root cause of the activity.\n"
    Reference = "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html#guardduty_findings-severity"
    SummaryAttributes = [
        "severity",
        "type",
        "title",
        "p_any_domain_names",
        "p_any_aws_arns",
        "p_any_aws_account_ids",
    ]
    Tests = aws_guard_duty_medium_severity_finding_tests

    def rule(self, event):
        if deep_get(event, "service", "additionalInfo", "sample"):
            # in case of sample data
            # https://docs.aws.amazon.com/guardduty/latest/ug/sample_findings.html
            return False
        return 4.0 <= float(event.get("severity", 0)) <= 6.9

    def title(self, event):
        return event.get("title")

    def alert_context(self, event):
        return aws_guardduty_context(event)
