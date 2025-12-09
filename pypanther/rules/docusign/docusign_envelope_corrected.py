from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.docusign import docusign_alert_context


@panther_managed
class DocusignConnectEnvelopeCorrected(Rule):
    id = "Docusign.Connect.EnvelopeCorrected-prototype"
    display_name = "DocuSign Envelope Corrected"
    log_types = [LogType.DOCUSIGN_CONNECT]
    tags = ["DocuSign", "Envelope", "Tampering"]
    default_severity = Severity.LOW
    default_description = "Detects when a DocuSign envelope is corrected after being sent. Frequent corrections could indicate document tampering attempts, process abuse, or suspicious modification of legal documents. Monitor for patterns of correction behavior that may indicate fraud.\n"
    default_runbook = "1. Review the envelope contents and what was corrected\n2. Verify if the correction was legitimate business process\n3. Check for patterns of envelope corrections by the same user\n4. Review the original and corrected document versions\n5. Consider investigating other envelopes sent by the same sender\n6. Verify recipient authentication for corrected envelopes\n"
    default_reference = "https://developer.docusign.com/docs/connect/events/"
    summary_attributes = ["data.envelopeId", "data.senderEmail", "data.email"]

    def rule(self, event):
        return event.get("event") == "envelope-corrected"

    def title(self, event):
        envelope_id = event.deep_get("data", "envelopeId", default="Unknown")
        sender_email = event.deep_get("data", "sender", "email", default="Unknown")
        return f"DocuSign envelope [{envelope_id}] corrected by [{sender_email}]"

    def alert_context(self, event):
        return docusign_alert_context(event)

    tests = [
        RuleTest(
            name="Envelope Corrected Event",
            expected_result=True,
            log={
                "event": "envelope-corrected",
                "uri": "/api/v2/accounts/12345/envelopes/abc123",
                "retryCount": 0,
                "configurationId": "config123",
                "apiVersion": "v2.1",
                "generatedDateTime": "2024-01-15T10:30:00.000Z",
                "data": {
                    "accountId": "12345",
                    "userId": "user123",
                    "envelopeId": "envelope123",
                    "recipientId": "recipient123",
                    "email": "frodo@lotr.com",
                    "senderEmail": "denethor@lotr.com",
                    "envelopeSummary": {"status": "corrected", "created": "2024-01-15T09:00:00.000Z"},
                    "envelopeDocuments": [{"documentId": "doc1", "name": "Contract.pdf", "pages": 5}],
                },
            },
        ),
        RuleTest(
            name="Envelope Sent Event",
            expected_result=False,
            log={
                "event": "envelope-sent",
                "uri": "/api/v2/accounts/12345/envelopes/abc123",
                "retryCount": 0,
                "configurationId": "config123",
                "apiVersion": "v2.1",
                "generatedDateTime": "2024-01-15T10:30:00.000Z",
                "data": {
                    "accountId": "12345",
                    "userId": "user123",
                    "envelopeId": "envelope123",
                    "senderEmail": "denethor@lotr.com",
                    "envelopeSummary": {"status": "sent", "created": "2024-01-15T09:00:00.000Z"},
                },
            },
        ),
        RuleTest(
            name="Different Event Type",
            expected_result=False,
            log={
                "event": "recipient-signed",
                "uri": "/api/v2/accounts/12345/envelopes/abc123/recipients/recipient123",
                "retryCount": 0,
                "configurationId": "config123",
                "apiVersion": "v2.1",
                "generatedDateTime": "2024-01-15T10:30:00.000Z",
                "data": {"accountId": "12345", "envelopeId": "envelope123", "recipientId": "recipient123"},
            },
        ),
    ]
