from panther_core import PantherEvent

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSCloudTrailSESCheckIdentityVerifications(Rule):
    id = "AWS.CloudTrail.SES.CheckIdentityVerifications-prototype"
    display_name = "AWS CloudTrail SES Check Identity Verifications"
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.INFO
    create_alert = False
    default_reference = "https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ses-enumerate/\n"
    tags = ["AWS CloudTrail", "Beta"]

    def rule(self, event: PantherEvent) -> bool:
        return event.get("eventName") == "GetIdentityVerificationAttributes"

    def alert_context(self, event: PantherEvent) -> dict:
        context = aws_rule_context(event)
        context["accountRegion"] = f"{event.get('recipientAccountId')}_{event.get('eventRegion')}"
        return context

    tests = [
        RuleTest(
            name="GetIdentityVerificationStatus Event",
            expected_result=True,
            log={
                "p_event_time": "2025-01-20 16:52:14.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2025-01-20 17:00:54.142940079",
                "additionalEventData": {"SignatureVersion": "4"},
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "05197e93-992f-4476-899a-a6f53c9a462c",
                "eventName": "GetIdentityVerificationAttributes",
                "eventSource": "ses.amazonaws.com",
                "eventTime": "2025-01-20 16:52:14.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "readOnly": True,
                "recipientAccountId": "111122223333",
                "requestID": "e3b6e034-97ce-4d43-a7d2-1e718f3ebf32",
                "requestParameters": {
                    "identities": ["acme.com", "bobson.dugnutt@acme.com", "sleve.mcdichael@yahoo.com"],
                },
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "email.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "example-user-agent",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/bobson.dugnutt",
                    "principalId": "SAMPLE_PRINCIPAL_ID:bobson.dugnutt",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-01-20T15:58:59Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
                            "principalId": "SAMPLE_PRINCIPAL_ID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
    ]
