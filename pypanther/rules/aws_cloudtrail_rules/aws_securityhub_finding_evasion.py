from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context
from pypanther.log_types import LogType

aws_security_hub_finding_evasion_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="CreateInsight",
        ExpectedResult=False,
        Log={
            "awsRegion": "us-west-2",
            "eventID": "3dabcebf-35b0-443f-a1a2-26e186ce23bf",
            "eventName": "CreateInsight",
            "eventSource": "securityhub.amazonaws.com",
            "eventTime": "2018-11-25T01:02:18Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "readOnly": False,
            "recipientAccountId": "012345678901",
            "requestID": "c0fffccd-f04d-11e8-93fc-ddcd14710066",
            "requestParameters": {
                "Filters": {},
                "Name": "Test Insight",
                "ResultField": "ResourceId",
            },
            "responseElements": {
                "InsightArn": "arn:aws:securityhub:us-west-2:0123456789010:insight/custom/f4c4890b-ac6b-4c26-95f9-e62cc46f3055"
            },
            "sourceIPAddress": "205.251.233.179",
            "userAgent": "aws-cli/1.11.76 Python/2.7.10 Darwin/17.7.0 botocore/1.5.39",
            "userIdentity": {
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "accountId": "012345678901",
                "arn": "arn:aws:iam::012345678901:user/TestUser",
                "principalId": "AIDAJK6U5DS22IAVUI7BW",
                "type": "IAMUser",
                "userName": "TestUser",
            },
        },
    ),
    PantherRuleTest(
        Name="DeleteInsight",
        ExpectedResult=True,
        Log={
            "awsRegion": "us-west-2",
            "eventID": "3dabcebf-35b0-443f-a1a2-26e186ce23bf",
            "eventName": "DeleteInsight",
            "eventSource": "securityhub.amazonaws.com",
            "eventTime": "2018-11-25T01:02:18Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "readOnly": False,
            "recipientAccountId": "012345678901",
            "requestID": "c0fffccd-f04d-11e8-93fc-ddcd14710066",
            "requestParameters": {
                "Filters": {},
                "Name": "Test Insight",
                "ResultField": "ResourceId",
            },
            "responseElements": {
                "InsightArn": "arn:aws:securityhub:us-west-2:0123456789010:insight/custom/f4c4890b-ac6b-4c26-95f9-e62cc46f3055"
            },
            "sourceIPAddress": "205.251.233.179",
            "userAgent": "aws-cli/1.11.76 Python/2.7.10 Darwin/17.7.0 botocore/1.5.39",
            "userIdentity": {
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "accountId": "012345678901",
                "arn": "arn:aws:iam::012345678901:user/TestUser",
                "principalId": "AIDAJK6U5DS22IAVUI7BW",
                "type": "IAMUser",
                "userName": "TestUser",
            },
        },
    ),
    PantherRuleTest(
        Name="UpdateFindings",
        ExpectedResult=True,
        Log={
            "awsRegion": "us-west-2",
            "eventID": "3dabcebf-35b0-443f-a1a2-26e186ce23bf",
            "eventName": "UpdateFindings",
            "eventSource": "securityhub.amazonaws.com",
            "eventTime": "2018-11-25T01:02:18Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "readOnly": False,
            "recipientAccountId": "012345678901",
            "requestID": "c0fffccd-f04d-11e8-93fc-ddcd14710066",
            "requestParameters": {
                "Filters": {},
                "Name": "Test Insight",
                "ResultField": "ResourceId",
            },
            "responseElements": {
                "InsightArn": "arn:aws:securityhub:us-west-2:0123456789010:insight/custom/f4c4890b-ac6b-4c26-95f9-e62cc46f3055"
            },
            "sourceIPAddress": "205.251.233.179",
            "userAgent": "aws-cli/1.11.76 Python/2.7.10 Darwin/17.7.0 botocore/1.5.39",
            "userIdentity": {
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "accountId": "012345678901",
                "arn": "arn:aws:iam::012345678901:user/TestUser",
                "principalId": "AIDAJK6U5DS22IAVUI7BW",
                "type": "IAMUser",
                "userName": "TestUser",
            },
        },
    ),
]


class AWSSecurityHubFindingEvasion(PantherRule):
    Description = "Detections modification of findings in SecurityHub"
    DisplayName = "AWS SecurityHub Finding Evasion"
    Reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    Reference = "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-insights-view-take-action.html"
    Severity = PantherSeverity.High
    LogTypes = [LogType.AWS_CloudTrail]
    RuleID = "AWS.SecurityHub.Finding.Evasion-prototype"
    Tests = aws_security_hub_finding_evasion_tests
    EVASION_OPERATIONS = ["BatchUpdateFindings", "DeleteInsight", "UpdateFindings", "UpdateInsight"]

    def rule(self, event):
        if (
            event.get("eventSource", "") == "securityhub.amazonaws.com"
            and event.get("eventName", "") in self.EVASION_OPERATIONS
        ):
            return True
        return False

    def title(self, event):
        return f"SecurityHub Findings have been modified in account: [{event.get('recipientAccountId', '')}]"

    def alert_context(self, event):
        return aws_rule_context(event)
