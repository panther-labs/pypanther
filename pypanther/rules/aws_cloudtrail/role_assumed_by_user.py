from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

role_assumedby_user_tests: list[RuleTest] = [
    RuleTest(
        name="Role Assumed by Service",
        expected_result=False,
        log={
            "awsRegion": "us-west-2",
            "eventCategory": "Management",
            "eventID": "1f3d7d49-6637-3304-b959-9be15f20215d",
            "eventName": "AssumeRole",
            "eventSource": "sts.amazonaws.com",
            "eventTime": "2024-06-02 20:27:12",
            "eventType": "AwsApiCall",
            "eventVersion": "1.08",
            "managementEvent": True,
            "readOnly": True,
            "recipientAccountId": "123456789123",
            "requestID": "a0dda101-6e27-4f88-8250-f3d475f88b56",
            "requestParameters": {
                "roleArn": "arn:aws:iam::123456789123:role/my_role_arn",
                "roleSessionName": "awslambda_55_20240602202712548",
            },
            "resources": [
                {
                    "accountId": "123456789123",
                    "arn": "arn:aws:iam::123456789123:role/my_role_arn",
                    "type": "AWS::IAM::Role",
                },
            ],
            "responseElements": {
                "credentials": {
                    "accessKeyId": "REDACTED",
                    "expiration": "Jun 2, 2024, 10:37:12 PM",
                    "sessionToken": "REDACTED",
                },
            },
            "sharedEventID": "95e84e79-100a-40a6-985e-3c9c4b41f622",
            "sourceIPAddress": "lambda.amazonaws.com",
            "userAgent": "lambda.amazonaws.com",
            "userIdentity": {"invokedBy": "lambda.amazonaws.com", "type": "AWSService"},
        },
    ),
]


@panther_managed
class RoleAssumedbyUser(Rule):
    id = "Role.Assumed.by.User-prototype"
    display_name = "SIGNAL - Role Assumed by User"
    enabled = False
    create_alert = False
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.INFO
    tests = role_assumedby_user_tests

    def rule(self, event):
        aws_service = event.deep_get("userIdentity", "type") == "AWSService"
        return all(
            [event.get("eventName") == "AssumeRole", event.deep_get("requestParameters", "roleArn"), not aws_service],
        )
