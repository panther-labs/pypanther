from panther_core import PantherEvent

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSCloudTrailSESCheckSendQuota(Rule):
    id = "AWS.CloudTrail.SES.CheckSendQuota-prototype"
    display_name = "AWS CloudTrail SES Check Send Quota"
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.INFO
    create_alert = False
    default_description = "Detect when someone checks how many emails can be delivered via SES \n"
    default_reference = "https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ses-enumerate/\n"
    tags = ["AWS CloudTrail", "SES", "Beta"]

    def rule(self, event: PantherEvent) -> bool:
        return event.get("eventName") == "GetSendQuota"

    def alert_context(self, event: PantherEvent) -> dict:
        context = aws_rule_context(event)
        context["accountRegion"] = f"{event.get('recipientAccountId')}_{event.get('eventRegion')}"
        return context

    tests = [
        RuleTest(
            name="GetSendQuota Event",
            expected_result=True,
            log={
                "p_event_time": "2025-01-20 16:52:14.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2025-01-20 17:00:54.217261818",
                "additionalEventData": {"SignatureVersion": "4"},
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "141c7b0f-3ec3-40bd-b551-5a33d1a794b4",
                "eventName": "GetSendQuota",
                "eventSource": "ses.amazonaws.com",
                "eventTime": "2025-01-20 16:52:14.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "readOnly": True,
                "recipientAccountId": "111122223333",
                "requestID": "6495a102-3900-47fc-a8b4-88e4b4e56442",
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
