from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSSecretsManagerRetrieveSecrets(Rule):
    id = "AWS.SecretsManager.RetrieveSecrets-prototype"
    display_name = "EC2 Secrets Manager Retrieve Secrets"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Credential Access", "Stratus Red Team", "Beta"]
    reports = {"MITRE ATT&CK": ["TA0006:T1552"]}
    default_severity = Severity.INFO
    default_description = "An attacker attempted to retrieve a high number of Secrets Manager secrets, through secretsmanager:GetSecretValue."
    default_runbook = "https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud"
    default_reference = (
        "https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.secretsmanager-retrieve-secrets/"
    )
    threshold = 20
    dedup_period_minutes = 1440
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]

    def rule(self, event):
        if (
            event.get("eventName") == "GetSecretValue"
            and (not aws_cloudtrail_success(event))
            and (event.get("errorCode") == "AccessDenied")
        ):
            return True
        return False

    def title(self, event):
        user = event.udm("actor_user")
        return f"[{user}] is not authorized to retrieve secrets from AWS Secrets Manager"

    def alert_context(self, event):
        return aws_rule_context(event) | {
            "errorCode": event.get("errorCode"),
            "errorMessage": event.get("errorMessage"),
        }

    tests = [
        RuleTest(
            name="GetSecretValue Denied",
            expected_result=True,
            log={
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "dfd6d93a-2ce6-4dbe-8939-86b8ba67c868",
                "eventName": "GetSecretValue",
                "errorCode": "AccessDenied",
                "eventSource": "secretsmanager.amazonaws.com",
                "eventTime": "2024-10-17 21:48:45.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.09",
                "managementEvent": True,
                "readOnly": True,
                "recipientAccountId": "123123123123",
                "requestID": "5128b35f-0daf-4c5e-948a-21a1c507968c",
                "requestParameters": {
                    "secretId": "arn:aws:secretsmanager:us-west-2:123123123123:secret:stratus-red-team-retrieve-secret-3-gscOm8",
                    "versionId": "7DC59E8B-63AE-454D-B7A4-8A7D64AB05E7",
                },
                "sourceIPAddress": "123.123.123.123",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "secretsmanager.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "APN/1.0 HashiCorp/1.0 Terraform/1.1.2 (+https://www.terraform.io) terraform-provider-aws/3.76.1 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.44.157 (go1.19.3; darwin; arm64) HashiCorp-terraform-exec/0.17.3",
                "userIdentity": {
                    "accessKeyId": "ASIASXP6SDP2LKLKYYC4",
                    "accountId": "123123123123",
                    "arn": "arn:aws:sts::123123123123:assumed-role/AWSReservedSSO_DevAdmin_635426549a280cc6/evil.genius",
                    "principalId": "AROASXP6SDP2F4WLQVARB:evil.genius",
                    "sessionContext": {
                        "attributes": {"creationDate": "2024-10-17T21:48:13Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "123123123123",
                            "arn": "arn:aws:iam::123123123123:role/aws-reserved/sso.amazonaws.com/us-west-2/AWSReservedSSO_DevAdmin_635426549a280cc6",
                            "principalId": "AROASXP6SDP2F4WLQVARB",
                            "type": "Role",
                            "userName": "AWSReservedSSO_DevAdmin_635426549a280cc6",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
    ]
