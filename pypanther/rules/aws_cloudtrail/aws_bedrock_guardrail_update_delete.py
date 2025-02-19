from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSBedrockGuardrailUpdateDelete(Rule):
    id = "AWS.Bedrock.GuardrailUpdateDelete-prototype"
    display_name = "AWS Bedrock Guardrail Updated or Deleted"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = [
        "AWS",
        "Bedrock",
        "Generative AI Guardrails",
        "AML.T0054",
        "LLM Jailbreak",
        "Impair Defenses: Disable or Modify Tools",
        "Defense Evasion",
    ]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0005:T1562.001"]}
    default_description = "An Amazon Bedrock Guardrail was updated or deleted. Amazon Bedrock Guardrails are used to implement application-specific safeguards based on your use cases and responsible AI policies. Updating or deleting a guardrail can have security implications to your AI workloads.\n"
    default_runbook = "Review the guardrail update or deletion to ensure that it was authorized and that it does not introduce security risks to your AI workloads. If the guardrail update or deletion was unauthorized, investigate the incident and take appropriate action. https://atlas.mitre.org/mitigations/AML.M0020\n"
    default_reference = "https://docs.aws.amazon.com/bedrock/latest/APIReference/API_DeleteGuardrail.html"
    summary_attributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    GUARDRAIL_EVENTS = {"DeleteGuardrail", "UpdateGuardrail"}

    def rule(self, event):
        if (
            event.get("eventSource") == "bedrock.amazonaws.com"
            and event.get("eventName") in self.GUARDRAIL_EVENTS
            and aws_cloudtrail_success(event)
        ):
            return True
        return False

    def title(self, event):
        user = event.udm("actor_user")
        guardrail = event.deep_get("requestParameters", "guardrailIdentifier")
        action = event.get("eventName").replace("Guardrail", "").lower()
        return f"User [{user}] {action}d Bedrock guardrail [{guardrail}]"

    def severity(self, event):
        if event.get("eventName") == "UpdateGuardrail":
            return "LOW"
        return "DEFAULT"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Guardrail Updated",
            expected_result=True,
            log={
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "4d482238-d0c5-4337-800f-d1ed79957fd4",
                "eventName": "UpdateGuardrail",
                "eventSource": "bedrock.amazonaws.com",
                "eventTime": "2025-01-21 17:39:10.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.09",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "123123123123",
                "requestID": "4ebcfaab-52e6-4027-9307-dbfe671b1cdb",
                "requestParameters": {"guardrailIdentifier": "cmy5azq5koeo", "name": "HIDDEN_DUE_TO_SECURITY_REASONS"},
                "responseElements": {
                    "guardrailArn": "arn:aws:bedrock:us-west-2:123123123123:guardrail/cmy5azq5koeo",
                    "guardrailId": "cmy5azq5koeo",
                    "updatedAt": "2025-01-21T17:39:10.379877250Z",
                    "version": "DRAFT",
                },
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
        RuleTest(
            name="Guardrail Deleted",
            expected_result=True,
            log={
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "3105145b-d0ca-41ab-a0fd-73f4f31ccbd1",
                "eventName": "DeleteGuardrail",
                "eventSource": "bedrock.amazonaws.com",
                "eventTime": "2025-01-21 18:12:33.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.09",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "123123123123",
                "requestID": "6e6cadb2-ad15-4c46-9900-fd1888e01ee1",
                "requestParameters": {"guardrailIdentifier": "cmy5azq5koeo"},
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
