from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context, lookup_aws_account_name


@panther_managed
class AWSCloudTrailStopped(Rule):
    id = "AWS.CloudTrail.Stopped-prototype"
    display_name = "CloudTrail Stopped"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Security Control", "DemoThreatHunting", "Defense Evasion:Impair Defenses"]
    reports = {"CIS": ["3.5"], "MITRE ATT&CK": ["TA0005:T1562"]}
    default_severity = Severity.MEDIUM
    default_description = "A CloudTrail Trail was modified.\n"
    default_runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-cloudtrail-modified"
    default_reference = (
        "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-delete-trails-console.html"
    )
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    # API calls that are indicative of CloudTrail changes
    CLOUDTRAIL_STOP_DELETE = {"DeleteTrail", "StopLogging"}

    def rule(self, event):
        return aws_cloudtrail_success(event) and event.get("eventName") in self.CLOUDTRAIL_STOP_DELETE

    def dedup(self, event):
        # Merge on the CloudTrail ARN
        return event.deep_get("requestParameters", "name", default="<UNKNOWN_NAME>")

    def title(self, event):
        return f"CloudTrail [{self.dedup(event)}] in account [{lookup_aws_account_name(event.get('recipientAccountId'))}] was stopped/deleted"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="CloudTrail Was Stopped",
            expected_result=True,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "tester",
                    "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "1111",
                            "arn": "arn:aws:iam::123456789012:role/tester",
                            "accountId": "123456789012",
                            "userName": "Tester",
                        },
                        "webIdFederationData": {},
                        "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
                    },
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventName": "StopLogging",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {"name": "arn:aws:cloudtrail:us-west-2:123456789012:trail/example-trail"},
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="CloudTrail Was Started",
            expected_result=False,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "111:panther-snapshot-scheduler",
                    "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "false", "creationDate": "2019-01-01T00:00:00Z"},
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "1111",
                            "arn": "arn:aws:iam::123456789012:role/tester",
                            "accountId": "123456789012",
                            "userName": "tester",
                        },
                    },
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventName": "StartLogging",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla",
                "requestParameters": {
                    "encryptionContext": {
                        "aws:lambda:FunctionArn": "arn:aws:lambda:us-west-2:123456789012:function:test-function",
                    },
                },
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "readOnly": True,
                "resources": [
                    {
                        "ARN": "arn:aws:kms:us-west-2:123456789012:key/1",
                        "accountId": "123456789012",
                        "type": "AWS::KMS::Key",
                    },
                ],
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="Error Stopping CloudTrail",
            expected_result=False,
            log={
                "eventVersion": "1.05",
                "errorCode": "InvalidTrailNameException",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "tester",
                    "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "1111",
                            "arn": "arn:aws:iam::123456789012:role/tester",
                            "accountId": "123456789012",
                            "userName": "Tester",
                        },
                        "webIdFederationData": {},
                        "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
                    },
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventName": "StopLogging",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {"name": "arn:aws:cloudtrail:us-west-2:123456789012:trail/example-trail"},
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
    ]
