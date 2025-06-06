from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSIAMAccessKeyCompromised(Rule):
    id = "AWS.IAM.AccessKeyCompromised-prototype"
    display_name = "AWS Access Key Uploaded to Github"
    log_types = [LogType.AWS_CLOUDTRAIL]
    reports = {"MITRE ATT&CK": ["TA0006:T1552"]}
    tags = ["AWS", "Credential Access:Unsecured Credentials"]
    default_severity = Severity.HIGH
    default_description = "A users static AWS API key was uploaded to a public github repo."
    default_runbook = "Determine the key owner, disable/delete key, and delete the user to resolve the AWS case. If user needs a new IAM give them a stern talking to first."
    default_reference = "https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning"
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
        return event.deep_get("userIdentity", "userName")

    def title(self, event):
        return f"{self.dedup(event)}'s access key ID [{event.deep_get('userIdentity', 'accessKeyId')}] was uploaded to a public GitHub repo"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="An AWS Access Key was Uploaded to Github",
            expected_result=True,
            log={
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
        RuleTest(
            name="Request Param is null",
            expected_result=False,
            log={
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
