from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSBedrockDeleteModelInvocationLoggingConfiguration(Rule):
    id = "AWS.Bedrock.DeleteModelInvocationLoggingConfiguration-prototype"
    display_name = "AWS Bedrock Model Invocation Logging Configuration Deleted"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Bedrock", "Impair Defenses: Impair Command History Logging", "Defense Evastion"]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0005:T1562.003"]}
    default_description = "An Amazon Bedrock Model Invocation Logging Configuration was deleted. Use model invocation logging to collect metadata, requests, and responses for all model invocations in your account. Deleting a model invocation logging configuration can have security implications to your AI workloads.\n"
    default_runbook = "Review the model invocation logging configuration deletion to ensure that it was authorized and that it does not introduce security risks to your AI workloads. If the model invocation logging configuration deletion was unauthorized, investigate the incident and take appropriate action.\n"
    default_reference = "https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html"
    summary_attributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]

    def rule(self, event):
        if (
            event.get("eventSource") == "bedrock.amazonaws.com"
            and event.get("eventName") == "DeleteModelInvocationLoggingConfiguration"
            and aws_cloudtrail_success(event)
        ):
            return True
        return False

    def title(self, event):
        user = event.udm("actor_user")
        return f"User [{user}] deleted Bedrock model invocation logging configuration"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Model Invocation Logging Configuration Deleted",
            expected_result=True,
            log={
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "28773860-a4fd-47c7-a215-6f0e6e6e532f",
                "eventName": "DeleteModelInvocationLoggingConfiguration",
                "eventSource": "bedrock.amazonaws.com",
                "eventTime": "2025-01-21 17:49:47.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.09",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "123123123123",
                "requestID": "7b9b25ca-be2d-4428-9793-0a677c32b823",
                "sessionCredentialFromConsole": True,
                "sourceIPAddress": "161.97.249.211",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "bedrock.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "userIdentity": {
                    "accessKeyId": "ASIAQWERQWERQWERQWER",
                    "accountId": "123123123123",
                    "arn": "arn:aws:sts::123123123123:assumed-role/DevAdmin/dr.evil",
                    "principalId": "AROAQWERQWERQWERQWER:dr.evil",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-01-21T16:08:03Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "123123123123",
                            "arn": "arn:aws:iam::123123123123:role/aws-reserved/sso.amazonaws.com/us-west-2/DevAdmin",
                            "principalId": "AROAQWERQWERQWERQWER",
                            "type": "Role",
                            "userName": "DevAdmin",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="List Guardrails",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "906c4056-df1e-4565-a40b-2ba216a0c849",
                "eventName": "ListGuardrails",
                "eventSource": "bedrock.amazonaws.com",
                "eventTime": "2025-01-21 18:12:33.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.09",
                "managementEvent": True,
                "readOnly": True,
                "recipientAccountId": "123123123123",
                "requestID": "9219ab18-cddf-4376-afc6-cc4edf2c2f0f",
                "requestParameters": {"maxResults": 1000},
                "sessionCredentialFromConsole": True,
                "sourceIPAddress": "123.123.123.123",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "bedrock.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "userIdentity": {
                    "accessKeyId": "ASIAQWERQWERQWERQWER",
                    "accountId": "123123123123",
                    "arn": "arn:aws:sts::123123123123:assumed-role/DevAdmin/dr.evil",
                    "principalId": "AROAQWERQWERQWERQWER:dr.evil",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-01-21T16:08:03Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "123123123123",
                            "arn": "arn:aws:iam::123123123123:role/aws-reserved/sso.amazonaws.com/us-west-2/DevAdmin",
                            "principalId": "AROAQWERQWERQWERQWER",
                            "type": "Role",
                            "userName": "DevAdmin",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
    ]
