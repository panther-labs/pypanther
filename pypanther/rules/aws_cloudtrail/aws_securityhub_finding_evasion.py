from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSSecurityHubFindingEvasion(Rule):
    default_description = "Detections modification of findings in SecurityHub"
    display_name = "AWS SecurityHub Finding Evasion"
    reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    default_reference = (
        "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-insights-view-take-action.html"
    )
    default_severity = Severity.HIGH
    log_types = [LogType.AWS_CLOUDTRAIL]
    id = "AWS.SecurityHub.Finding.Evasion-prototype"
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

    tests = [
        RuleTest(
            name="CreateInsight",
            expected_result=False,
            log={
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
                "requestParameters": {"Filters": {}, "Name": "Test Insight", "ResultField": "ResourceId"},
                "responseElements": {
                    "InsightArn": "arn:aws:securityhub:us-west-2:0123456789010:insight/custom/f4c4890b-ac6b-4c26-95f9-e62cc46f3055",
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
        RuleTest(
            name="DeleteInsight",
            expected_result=True,
            log={
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
                "requestParameters": {"Filters": {}, "Name": "Test Insight", "ResultField": "ResourceId"},
                "responseElements": {
                    "InsightArn": "arn:aws:securityhub:us-west-2:0123456789010:insight/custom/f4c4890b-ac6b-4c26-95f9-e62cc46f3055",
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
        RuleTest(
            name="UpdateFindings",
            expected_result=True,
            log={
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
                "requestParameters": {"Filters": {}, "Name": "Test Insight", "ResultField": "ResourceId"},
                "responseElements": {
                    "InsightArn": "arn:aws:securityhub:us-west-2:0123456789010:insight/custom/f4c4890b-ac6b-4c26-95f9-e62cc46f3055",
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
