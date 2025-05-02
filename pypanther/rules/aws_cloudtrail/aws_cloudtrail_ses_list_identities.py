from panther_core import PantherEvent

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSCloudTrailSESListIdentities(Rule):
    id = "AWS.CloudTrail.SES.ListIdentities-prototype"
    display_name = "AWS CloudTrail SES List Identities"
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.INFO
    create_alert = False
    default_reference = "https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ses-enumerate/\n"
    tags = ["AWS CloudTrail", "SES", "Beta"]

    def rule(self, event: PantherEvent) -> bool:
        return event.get("eventName") == "ListIdentities"

    def alert_context(self, event: PantherEvent) -> dict:
        context = aws_rule_context(event)
        context["accountRegion"] = f"{event.get('recipientAccountId')}_{event.get('eventRegion')}"
        return context

    tests = [
        RuleTest(
            name="ListIdentities Event",
            expected_result=True,
            log={
                "p_event_time": "2025-01-20 16:52:14.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2025-01-20 17:00:54.217385551",
                "additionalEventData": {"SignatureVersion": "4"},
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "7c41bbec-52c5-49cb-80aa-88f295d490fd",
                "eventName": "ListIdentities",
                "eventSource": "ses.amazonaws.com",
                "eventTime": "2025-01-20 16:52:14.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "readOnly": True,
                "recipientAccountId": "111122223333",
                "requestID": "7bdf32e1-6e53-4752-b745-2cb37788a23c",
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
