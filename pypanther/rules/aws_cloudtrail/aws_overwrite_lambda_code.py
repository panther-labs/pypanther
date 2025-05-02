from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSLambdaUpdateFunctionCode(Rule):
    id = "AWS.Lambda.UpdateFunctionCode-prototype"
    display_name = "Lambda Update Function Code"
    create_alert = False
    log_types = [LogType.AWS_CLOUDTRAIL]
    reports = {"MITRE ATT&CK": ["TA0007:T1078"]}
    default_severity = Severity.INFO
    tags = ["Beta"]
    default_description = (
        "Identifies when the code of a Lambda function is updated, which could indicate a potential security risk.\n"
    )
    default_runbook = "Verify the event details and the user that triggered the event. If the event is expected, no action is required. If the event is unexpected, investigate the user and the function that was updated."
    default_reference = "https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-overwrite-code/"

    def rule(self, event):
        return (
            aws_cloudtrail_success(event)
            and event.get("eventSource") == "lambda.amazonaws.com"
            and event.get("eventName").startswith("UpdateFunctionCode")
        )

    def title(self, event):
        lambda_name = event.deep_get("responseElements", "functionName", default="LAMBDA_NAME_NOT_FOUND")
        return f"[AWS.CloudTrail] User [{event.udm('actor_user')}] updated Lambda function code for [{lambda_name}]"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Lambda Update Function Code Event",
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
                "eventSource": "lambda.amazonaws.com",
                "eventName": "UpdateFunctionCode20150331",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {"functionName": "my-lambda-function"},
                "responseElements": {"functionName": "my-lambda-function"},
                "requestID": "1",
                "eventID": "1",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
                "p_log_type": "AWS.CloudTrail",
            },
        ),
        RuleTest(
            name="Lambda Update Function Code Event v2",
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
                "eventSource": "lambda.amazonaws.com",
                "eventName": "UpdateFunctionCode20150331v2",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {"functionName": "my-lambda-function"},
                "responseElements": {"functionName": "my-lambda-function"},
                "requestID": "1",
                "eventID": "1",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
                "p_log_type": "AWS.CloudTrail",
            },
        ),
        RuleTest(
            name="Delete Function Event",
            expected_result=False,
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
                "eventSource": "lambda.amazonaws.com",
                "eventName": "DeleteFunction",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {"functionName": "my-lambda-function"},
                "responseElements": {"functionName": "my-lambda-function"},
                "requestID": "1",
                "eventID": "1",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
                "p_log_type": "AWS.CloudTrail",
            },
        ),
    ]
