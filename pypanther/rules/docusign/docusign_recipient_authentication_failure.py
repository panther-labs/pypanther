from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.docusign import docusign_alert_context, get_recipients


@panther_managed
class DocusignConnectRecipientAuthenticationFailure(Rule):
    id = "Docusign.Connect.RecipientAuthenticationFailure-prototype"
    display_name = "DocuSign Recipient Authentication Failure"
    log_types = [LogType.DOCUSIGN_CONNECT]
    tags = ["DocuSign", "Authentication"]
    default_severity = Severity.MEDIUM
    threshold = 5
    default_description = "Detects when a DocuSign recipient fails authentication while attempting to access an envelope. This could indicate attempted unauthorized access to sensitive documents or credential compromise.\n"
    default_runbook = "1. Review the recipient's email and authentication method used\n2. Check if this is a legitimate user having authentication issues\n3. Verify if the envelope contains sensitive information\n4. Consider blocking the recipient if suspicious activity is detected\n5. Review other envelopes sent to the same recipient\n"
    default_reference = "https://developer.docusign.com/docs/connect/events/"
    summary_attributes = ["data.email", "data.envelopeId", "data.authenticationStatus"]

    def rule(self, event):
        return event.get("event") == "recipient-authentication-failure"

    def title(self, event):
        recipients = get_recipients(event)
        recipient = (
            [
                recipient
                for recipient in recipients
                if recipient.get("recipientId") == event.deep_get("data", "recipientId")
            ][0]
            if recipients
            else {}
        )
        recipient_email = recipient.get("email", "Unknown")
        envelope_id = event.deep_get("data", "envelopeId", default="Unknown")
        return f"DocuSign recipient authentication failure for [{recipient_email}] on envelope [{envelope_id}]"

    def alert_context(self, event):
        return docusign_alert_context(event)

    tests = [
        RuleTest(
            name="Recipient Authentication Failure",
            expected_result=True,
            log={
                "event": "recipient-authentication-failure",
                "uri": "/api/v2/accounts/12345/envelopes/abc123/recipients/recipient123",
                "retryCount": 0,
                "configurationId": "config123",
                "apiVersion": "v2.1",
                "generatedDateTime": "2024-01-15T10:30:00.000Z",
                "data": {
                    "accountId": "12345",
                    "userId": "user123",
                    "recipientId": "recipient123",
                    "envelopeId": "envelope123",
                    "name": "John Doe",
                    "email": "sam@lotr.com",
                    "routingOrder": 1,
                    "authenticationStatus": "Failed",
                    "errorReason": "Invalid authentication credentials",
                    "method": "SMS",
                    "phoneNumber": "+1234567890",
                },
            },
        ),
        RuleTest(
            name="Successful Authentication",
            expected_result=False,
            log={
                "event": "recipient-authentication-success",
                "uri": "/api/v2/accounts/12345/envelopes/abc123/recipients/recipient123",
                "retryCount": 0,
                "configurationId": "config123",
                "apiVersion": "v2.1",
                "generatedDateTime": "2024-01-15T10:30:00.000Z",
                "data": {
                    "accountId": "12345",
                    "userId": "user123",
                    "recipientId": "recipient123",
                    "envelopeId": "envelope123",
                    "name": "John Doe",
                    "email": "sam@lotr.com",
                    "routingOrder": 1,
                    "authenticationStatus": "Success",
                    "method": "SMS",
                    "phoneNumber": "+1234567890",
                },
            },
        ),
        RuleTest(
            name="Different Event Type",
            expected_result=False,
            log={
                "event": "envelope-sent",
                "uri": "/api/v2/accounts/12345/envelopes/abc123",
                "retryCount": 0,
                "configurationId": "config123",
                "apiVersion": "v2.1",
                "generatedDateTime": "2024-01-15T10:30:00.000Z",
                "data": {"accountId": "12345", "envelopeId": "envelope123"},
            },
        ),
    ]
