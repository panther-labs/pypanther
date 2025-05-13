from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSPotentialBackdoorLambda(Rule):
    id = "AWS.Potential.Backdoor.Lambda-prototype"
    display_name = "AWS Potential Backdoor Lambda Function Through Resource-Based Policy"
    log_types = [LogType.AWS_CLOUDTRAIL]
    reports = {"MITRE ATT&CK": ["TA0007:T1078"]}
    default_severity = Severity.INFO
    tags = ["Beta"]
    default_description = (
        "Identifies when a permission is added to a Lambda function, which could indicate a potential security risk.\n"
    )
    default_runbook = "Make sure that the permission is legitimate and necessary. If not, remove the permission"
    default_reference = "https://docs.aws.amazon.com/lambda/latest/dg/API_AddPermission.html"
    ADD_PERMISSION_EVENTS = {"AddPermission20150331", "AddPermission20150331v2"}

    def rule(self, event):
        return (
            aws_cloudtrail_success(event)
            and event.get("eventSource") == "lambda.amazonaws.com"
            and (event.get("eventName") in self.ADD_PERMISSION_EVENTS)
        )

    def title(self, event):
        lambda_name = event.deep_get("requestParameters", "functionName", default="LAMBDA_NAME_NOT_FOUND")
        return f"[AWS.CloudTrail] User [{event.udm('actor_user')}] added permission to Lambda function [{lambda_name}]"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Lambda Add Permission Event",
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
                "eventName": "AddPermission20150331",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {"functionName": "my-lambda-function"},
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
                "p_log_type": "AWS.CloudTrail",
            },
        ),
        RuleTest(
            name="Lambda Add Permission Event v2",
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
                "eventName": "AddPermission20150331v2",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {"functionName": "my-lambda-function"},
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
                "p_log_type": "AWS.CloudTrail",
            },
        ),
        RuleTest(
            name="Lambda Remove Permission Event",
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
                "eventName": "RemovePermission",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {"functionName": "my-lambda-function"},
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
                "p_log_type": "AWS.CloudTrail",
            },
        ),
    ]
