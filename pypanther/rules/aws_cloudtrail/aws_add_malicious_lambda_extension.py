from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSLambdaUpdateFunctionConfiguration(Rule):
    id = "AWS.Lambda.UpdateFunctionConfiguration-prototype"
    display_name = "Lambda Update Function Configuration with Layers"
    log_types = [LogType.AWS_CLOUDTRAIL]
    reports = {"MITRE ATT&CK": ["TA0007:T1078"]}
    default_severity = Severity.INFO
    tags = ["Beta"]
    create_alert = False
    default_description = "Identifies when a Lambda function configuration is updated with layers, which could indicate a potential security risk.\n"
    default_runbook = "Make sure that the Lambda function configuration update is expected and authorized. If not, investigate the event further."
    default_reference = "https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-layer-extension/"

    def rule(self, event):
        if (
            aws_cloudtrail_success(event)
            and event.get("eventSource") == "lambda.amazonaws.com"
            and (event.get("eventName") == "UpdateFunctionConfiguration20150331v2")
            and event.deep_get("responseElements", "layers")
        ):
            return True
        return False

    def title(self, event):
        lambda_name = event.deep_get("responseElements", "functionName", default="LAMBDA_NAME_NOT_FOUND")
        return f"[AWS.CloudTrail] User [{event.udm('actor_user')}] updated Lambda function configuration with layers for [{lambda_name}]"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Lambda Update Function Configuration with Layers",
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
                "eventName": "UpdateFunctionConfiguration20150331v2",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {"functionName": "my-lambda-function"},
                "responseElements": {"layers": [{"arn": "arn:aws:lambda:us-west-2:123456789012:layer:my-layer:1"}]},
                "requestID": "1",
                "eventID": "1",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
                "p_log_type": "AWS.CloudTrail",
            },
        ),
        RuleTest(
            name="Lambda Update Function Configuration without Layers",
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
                "eventName": "UpdateFunctionConfiguration20150331v2",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {"functionName": "my-lambda-function"},
                "responseElements": {},
                "requestID": "1",
                "eventID": "1",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
                "p_log_type": "AWS.CloudTrail",
            },
        ),
    ]
