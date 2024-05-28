from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.log_types import LogType

awsiam_access_key_compromised_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="An AWS Access Key was Uploaded to Github",
        ExpectedResult=True,
        Log={
            "eventSource": "iam.amazonaws.com",
            "recipientAccountId": "123456789012",
            "responseElements": None,
            "userIdentity": {
                "type": "IAMUser",
                "userName": "compromised_user",
                "principalId": "XXXXXXXXXXXXXXXXXXX",
                "accessKeyId": "XXXXXXXXXXXXXXXXXXXXX",
                "arn": "arn:aws:iam::123456789012:user/compromised_user",
                "accountId": "123456789012",
            },
            "eventName": "PutUserPolicy",
            "eventVersion": "1.05",
            "userAgent": "aws-internal/3 aws-sdk-java/1.11.706 Linux/4.9.184-0.1.ac.235.83.329.metal1.x86_64 OpenJDK_64-Bit_Server_VM/25.242-b08 java/1.8.0_242 vendor/Oracle_Corporation",
            "requestParameters": {
                "policyDocument": '{"Version":"2012-10-17","Statement":[{"Sid":"Stmt1538161409","Effect":"Deny","Action":["lambda:CreateFunction","iam:AttachUserPolicy","iam:PutUserPolicy","organizations:InviteAccountToOrganization","ec2:RunInstances","iam:DetachUserPolicy","iam:CreateUser","lightsail:Create*","lightsail:Update*","ec2:StartInstances","ec2:RequestSpotInstances","iam:ChangePassword","iam:CreateLoginProfile","organizations:CreateOrganization","organizations:CreateAccount","lightsail:Delete*","iam:AttachGroupPolicy","iam:CreateAccessKey","iam:UpdateUser","iam:UpdateAccountPasswordPolicy","iam:DeleteUserPolicy","iam:PutUserPermissionsBoundary","iam:UpdateAccessKey","lightsail:DownloadDefaultKeyPair","iam:CreateInstanceProfile","lightsail:Start*","lightsail:GetInstanceAccessDetails","iam:CreateRole","iam:PutGroupPolicy","iam:AttachRolePolicy"],"Resource":["*"]}]}',
                "userName": "compromised_user",
                "policyName": "AWSExposedCredentialPolicy_DO_NOT_REMOVE",
            },
            "eventID": "1c2a53d1-58cc-41b3-85b8-bd7565370e0d",
            "eventType": "AwsApiCall",
            "sourceIPAddress": "72.21.217.97",
            "awsRegion": "us-east-1",
            "requestID": "27ca92a5-61cc-44aa-b875-042a25310064",
            "eventTime": "2020-04-10T06:22:08Z",
        },
    ),
    PantherRuleTest(
        Name="Request Param is null",
        ExpectedResult=False,
        Log={
            "eventSource": "iam.amazonaws.com",
            "recipientAccountId": "123456789012",
            "responseElements": None,
            "userIdentity": {
                "type": "IAMUser",
                "userName": "compromised_user",
                "principalId": "XXXXXXXXXXXXXXXXXXX",
                "accessKeyId": "XXXXXXXXXXXXXXXXXXXXX",
                "arn": "arn:aws:iam::123456789012:user/compromised_user",
                "accountId": "123456789012",
            },
            "eventName": "PutUserPolicy",
            "eventVersion": "1.05",
            "userAgent": "aws-internal/3 aws-sdk-java/1.11.706 Linux/4.9.184-0.1.ac.235.83.329.metal1.x86_64 OpenJDK_64-Bit_Server_VM/25.242-b08 java/1.8.0_242 vendor/Oracle_Corporation",
            "requestParameters": None,
            "eventID": "1c2a53d1-58cc-41b3-85b8-bd7565370e0d",
            "eventType": "AwsApiCall",
            "sourceIPAddress": "72.21.217.97",
            "awsRegion": "us-east-1",
            "requestID": "27ca92a5-61cc-44aa-b875-042a25310064",
            "eventTime": "2020-04-10T06:22:08Z",
        },
    ),
]


class AWSIAMAccessKeyCompromised(PantherRule):
    RuleID = "AWS.IAM.AccessKeyCompromised-prototype"
    DisplayName = "AWS Access Key Uploaded to Github"
    LogTypes = [LogType.AWS_CloudTrail]
    Reports = {"MITRE ATT&CK": ["TA0006:T1552"]}
    Tags = ["AWS", "Credential Access:Unsecured Credentials"]
    Severity = PantherSeverity.High
    Description = "A users static AWS API key was uploaded to a public github repo."
    Runbook = "Determine the key owner, disable/delete key, and delete the user to resolve the AWS case. If user needs a new IAM give them a stern talking to first."
    Reference = "https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning"
    Tests = awsiam_access_key_compromised_tests
    EXPOSED_CRED_POLICY = "AWSExposedCredentialPolicy_DO_NOT_REMOVE"

    def rule(self, event):
        request_params = event.get("requestParameters", {})
        if request_params:
            return (
                event.get("eventName") == "PutUserPolicy"
                and request_params.get("policyName") == self.EXPOSED_CRED_POLICY
            )
        return False

    def dedup(self, event):
        return deep_get(event, "userIdentity", "userName")

    def title(self, event):
        return f"{self.dedup(event)}'s access key ID [{deep_get(event, 'userIdentity', 'accessKeyId')}] was uploaded to a public GitHub repo"

    def alert_context(self, event):
        return aws_rule_context(event)
