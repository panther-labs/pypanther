from fnmatch import fnmatch

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSLAMBDACRUD(Rule):
    id = "AWS.LAMBDA.CRUD-prototype"
    display_name = "Lambda CRUD Actions"
    enabled = False
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Security Control", "Configuration Required"]
    reports = {"CIS": ["3.12"], "MITRE ATT&CK": ["TA0005:T1525"]}
    default_severity = Severity.HIGH
    default_description = "Unauthorized lambda Create, Read, Update, or Delete event occurred."
    default_runbook = "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html"
    default_reference = "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html"
    summary_attributes = ["eventSource", "eventName", "recipientAccountId", "awsRegion", "p_any_aws_arns"]
    LAMBDA_CRUD_EVENTS = {
        "AddPermission",
        "CreateAlias",
        "CreateEventSourceMapping",
        "CreateFunction",
        "DeleteAlias",
        "DeleteEventSourceMapping",
        "DeleteFunction",
        "PublishVersion",
        "RemovePermission",
        "UpdateAlias",
        "UpdateEventSourceMapping",
        "UpdateFunctionCode",
        "UpdateFunctionConfiguration",
    }
    ALLOWED_ROLES = ["*DeployRole"]

    def rule(self, event):
        if event.get("eventSource") == "lambda.amazonaws.com" and event.get("eventName") in self.LAMBDA_CRUD_EVENTS:
            for role in self.ALLOWED_ROLES:
                if fnmatch(event.deep_get("userIdentity", "arn", default="unknown-arn"), role):
                    return False
            return True
        return False

    def title(self, event):
        return f"[{event.deep_get('userIdentity', 'arn', default='unknown-arn')}] performed Lambda [{event.get('eventName')}] in [{event.get('recipientAccountId')} {event.get('awsRegion')}]."

    def dedup(self, event):
        return f"{event.deep_get('userIdentity', 'arn', default='unknown-arn')}"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Lambda DeleteFunction Unauthorized Account",
            expected_result=True,
            log={
                "eventVersion": "1.03",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "A1B2C3D4E5F6G7EXAMPLE",
                    "arn": "arn:aws:iam::999999999999:user/myUserName",
                    "accountId": "999999999999",
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "userName": "myUserName",
                },
                "eventTime": "2015-03-18T19:04:42Z",
                "eventSource": "lambda.amazonaws.com",
                "eventName": "DeleteFunction",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "127.0.0.1",
                "userAgent": "Python-httplib2/0.8 (gzip)",
                "requestParameters": {"functionName": "basic-node-task"},
                "responseElements": None,
                "requestID": "a2198ecc-cda1-11e4-aaa2-e356da31e4ff",
                "eventID": "20b84ce5-730f-482e-b2b2-e8fcc87ceb22",
                "eventType": "AwsApiCall",
                "recipientAccountId": "999999999999",
            },
        ),
        RuleTest(
            name="Lambda DeleteFunction Unauthorized User",
            expected_result=True,
            log={
                "eventVersion": "1.03",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "A1B2C3D4E5F6G7EXAMPLE",
                    "arn": "arn:aws:iam::123456789012:user/myUserName",
                    "accountId": "123456789012",
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "userName": "myUserName",
                },
                "eventTime": "2015-03-18T19:04:42Z",
                "eventSource": "lambda.amazonaws.com",
                "eventName": "DeleteFunction",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "127.0.0.1",
                "userAgent": "Python-httplib2/0.8 (gzip)",
                "requestParameters": {"functionName": "basic-node-task"},
                "responseElements": None,
                "requestID": "a2198ecc-cda1-11e4-aaa2-e356da31e4ff",
                "eventID": "20b84ce5-730f-482e-b2b2-e8fcc87ceb22",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="Lambda DeleteFunction Authorized Account",
            expected_result=False,
            log={
                "eventVersion": "1.03",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "A1B2C3D4E5F6G7EXAMPLE",
                    "arn": "arn:aws:iam::123456789012:user/DeployRole",
                    "accountId": "123456789012",
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "userName": "myUserName",
                },
                "eventTime": "2015-03-18T19:04:42Z",
                "eventSource": "lambda.amazonaws.com",
                "eventName": "DeleteFunction",
                "awsRegion": "us-west-1",
                "sourceIPAddress": "127.0.0.1",
                "userAgent": "Python-httplib2/0.8 (gzip)",
                "requestParameters": {"functionName": "basic-node-task"},
                "responseElements": None,
                "requestID": "a2198ecc-cda1-11e4-aaa2-e356da31e4ff",
                "eventID": "20b84ce5-730f-482e-b2b2-e8fcc87ceb22",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
    ]
