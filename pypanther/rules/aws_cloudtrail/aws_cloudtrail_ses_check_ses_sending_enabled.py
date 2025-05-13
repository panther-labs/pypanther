from panther_core import PantherEvent

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSCloudTrailSESCheckSESSendingEnabled(Rule):
    id = "AWS.CloudTrail.SES.CheckSESSendingEnabled-prototype"
    display_name = "AWS CloudTrail SES Check SES Sending Enabled"
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.INFO
    create_alert = False
    default_description = "Detect when a user inquires whether SES Sending is enabled.\n"
    default_reference = "https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ses-enumerate/\n"
    tags = ["AWS CloudTrail", "SES", "Beta"]

    def rule(self, event: PantherEvent) -> bool:
        return event.get("eventName") == "GetAccountSendingEnabled"

    def alert_context(self, event: PantherEvent) -> dict:
        context = aws_rule_context(event)
        context["accountRegion"] = f"{event.get('recipientAccountId')}_{event.get('eventRegion')}"
        return context

    tests = [
        RuleTest(
            name="CheckSendingEnabled Event",
            expected_result=True,
            log={
                "p_event_time": "2025-01-20 16:52:14.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2025-01-20 17:00:54.143061055",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "910326f5-5c2c-49b4-a963-702280f29208",
                "eventName": "GetAccountSendingEnabled",
                "eventSource": "ses.amazonaws.com",
                "eventTime": "2025-01-20 16:52:14.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "readOnly": True,
                "recipientAccountId": "111122223333",
                "requestID": "b88b794d-b419-47b0-9805-5af1de78a1e7",
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
