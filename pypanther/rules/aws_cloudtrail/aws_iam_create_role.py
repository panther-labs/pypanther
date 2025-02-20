from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSIAMCreateRole(Rule):
    id = "AWS.IAM.CreateRole-prototype"
    display_name = "IAM Role Created"
    log_types = [LogType.AWS_CLOUDTRAIL]
    create_alert = False
    reports = {"CIS": ["1.1"], "MITRE ATT&CK": ["TA0007:T1078"]}
    default_severity = Severity.INFO
    default_description = "An IAM role was created.\n"
    default_runbook = "Check if the action was expected."
    default_reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create.html"

    def rule(self, event):
        return aws_cloudtrail_success(event) and event.get("eventName") == "CreateRole"

    def alert_context(self, event):
        context = aws_rule_context(event)
        context["request_rolename"] = event.deep_get("requestParameters", "roleName", default="ROLENAME_NOT_FOUND")
        return context

    tests = [
        RuleTest(
            name="IAM Role Created",
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
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateRole",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {"roleName": "new-role"},
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="IAM Role Not Created",
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
                "eventSource": "iam.amazonaws.com",
                "eventName": "AttachUserPolicy",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {
                    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "userName": "new-user",
                },
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
    ]
