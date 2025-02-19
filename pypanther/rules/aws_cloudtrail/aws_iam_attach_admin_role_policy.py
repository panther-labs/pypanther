from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSIAMAttachAdminRolePolicy(Rule):
    id = "AWS.IAM.AttachAdminRolePolicy-prototype"
    display_name = "IAM Administrator Role Policy Attached"
    log_types = [LogType.AWS_CLOUDTRAIL]
    create_alert = False
    reports = {"CIS": ["1.1"], "MITRE ATT&CK": ["TA0007:T1078"]}
    default_severity = Severity.INFO
    default_description = (
        "An IAM role policy was attached with Administrator Access, which could indicate a potential security risk.\n"
    )
    default_runbook = "Check if the action was expected. If not, remove the policy from the role."
    default_reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"

    def rule(self, event):
        if not aws_cloudtrail_success(event) or event.get("eventName") != "AttachRolePolicy":
            return False
        policy = event.deep_get("requestParameters", "policyArn", default="POLICY_NOT_FOUND")
        return policy.endswith("AdministratorAccess")

    def alert_context(self, event):
        context = aws_rule_context(event)
        context["request_rolename"] = event.deep_get("requestParameters", "roleName", default="ROLENAME_NOT_FOUND")
        return context

    tests = [
        RuleTest(
            name="IAM Role Policy Attached with Administrator Access",
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
                "eventName": "AttachRolePolicy",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {
                    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "roleName": "new-role",
                },
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="IAM Role Policy Attached without Administrator Access",
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
                "eventName": "AttachRolePolicy",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "roleName": "new-role"},
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
    ]
