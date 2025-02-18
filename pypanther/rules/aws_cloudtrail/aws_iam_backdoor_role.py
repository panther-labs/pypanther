import json

from policyuniverse.policy import Policy

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSIAMBackdoorRole(Rule):
    id = "AWS.IAM.BackdoorRole-prototype"
    display_name = "IAM Role Policy Updated to Allow Internet Access"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Security Control", "IAM"]
    reports = {"CIS": ["1.1"], "MITRE ATT&CK": ["TA0007:T1078"]}
    default_severity = Severity.MEDIUM
    default_description = "An IAM role policy was updated to allow internet access, which could indicate a backdoor.\n"
    default_runbook = "Check if the action was authorized and if the policy was updated by a trusted user. If not, revert the policy and investigate the user"
    default_reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"

    def rule(self, event):
        if not aws_cloudtrail_success(event) or event.get("eventName") != "UpdateAssumeRolePolicy":
            return False
        policy = event.deep_get("requestParameters", "policyDocument", default="{}")
        return Policy(json.loads(policy)).is_internet_accessible()

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="IAM Role Policy Updated to Allow Internet Access",
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
                "eventName": "UpdateAssumeRolePolicy",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {
                    "policyDocument": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"12345"}}}]}',
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
            name="IAM Role Policy Updated Without Internet Access",
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
                "eventName": "UpdateAssumeRolePolicy",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {
                    "policyDocument": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}',
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
            name="IAM Role Policy Updated With No Policy Document",
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
                "eventName": "UpdateAssumeRolePolicy",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {},
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
    ]
