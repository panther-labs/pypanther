from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.docusign import docusign_alert_context, get_recipients


@panther_managed
class DocusignConnectRecipientDeclined(Rule):
    id = "Docusign.Connect.RecipientDeclined-prototype"
    display_name = "DocuSign Recipient Declined Envelope"
    log_types = [LogType.DOCUSIGN_CONNECT]
    tags = ["DocuSign", "Recipient", "Declined", "Business Process"]
    default_severity = Severity.LOW
    default_description = "Detects when a DocuSign recipient declines to sign an envelope. While often legitimate business activity, frequent declines or patterns of declines may indicate issues with document validity, recipient concerns about authenticity, or potential fraud attempts.\n"
    default_runbook = "1. Review the envelope contents and recipients\n2. Check if the decline reason was provided\n3. Verify if this is expected business behavior\n4. Monitor for patterns of declines for the same envelope or sender\n5. Consider reaching out to the recipient for clarification\n6. Review if the envelope was sent to the correct recipient\n"
    default_reference = "https://developer.docusign.com/docs/connect/events/"
    summary_attributes = ["data.email", "data.envelopeId", "data.senderEmail"]

    def rule(self, event):
        return event.get("event") == "recipient-declined"

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
        return f"DocuSign recipient [{recipient_email}] declined envelope [{envelope_id}]"

    def alert_context(self, event):
        return docusign_alert_context(event)

    tests = [
        RuleTest(
            name="Recipient Declined Event",
            expected_result=True,
            log={
                "event": "recipient-declined",
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
                    "senderEmail": "denethor@lotr.com",
                    "routingOrder": 1,
                    "terminationReason": "Recipient declined to sign",
                    "envelopeSummary": {"status": "declined", "created": "2024-01-15T09:00:00.000Z"},
                },
            },
        ),
        RuleTest(
            name="Recipient Signed Event",
            expected_result=False,
            log={
                "event": "recipient-signed",
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
                    "envelopeSummary": {"status": "signed", "created": "2024-01-15T09:00:00.000Z"},
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
