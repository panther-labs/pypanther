from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.docusign import docusign_alert_context


@panther_managed
class DocusignConnectEnvelopeVoided(Rule):
    id = "Docusign.Connect.EnvelopeVoided-prototype"
    display_name = "DocuSign Envelope Voided"
    log_types = [LogType.DOCUSIGN_CONNECT]
    tags = ["DocuSign", "Envelope", "Fraud"]
    default_severity = Severity.MEDIUM
    default_description = "Detects when a DocuSign envelope is voided. Frequent voiding of envelopes could indicate fraudulent activity, document tampering attempts, or process abuse. Monitor for patterns of voiding behavior.\n"
    default_runbook = "1. Review the envelope contents and recipients\n2. Verify if the voiding was legitimate or suspicious\n3. Check for patterns of envelope voiding by the same user\n4. Review the termination reason for additional context\n5. Consider investigating other envelopes sent by the same sender\n"
    default_reference = "https://developer.docusign.com/docs/connect/events/"
    summary_attributes = ["data.envelopeId", "data.senderEmail", "data.terminationReason"]

    def rule(self, event):
        return event.get("event") == "envelope-voided"

    def title(self, event):
        envelope_id = event.deep_get("data", "envelopeId", default="Unknown")
        sender_email = event.deep_get("data", "sender", "email", default="Unknown")
        return f"DocuSign envelope [{envelope_id}] voided by [{sender_email}]"

    def alert_context(self, event):
        return docusign_alert_context(event) | {
            "voided_reason": event.deep_get("data", "envelopeSummary", "voidedReason"),
            "voided_date_time": event.deep_get("data", "envelopeSummary", "voidedDateTime"),
        }

    tests = [
        RuleTest(
            name="Envelope Voided Event",
            expected_result=True,
            log={
                "event": "envelope-voided",
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
                    "terminationReason": "User voided envelope",
                    "terminated_by": "user123",
                    "envelopeSummary": {"status": "voided", "created": "2024-01-15T09:00:00.000Z"},
                },
            },
        ),
        RuleTest(
            name="Envelope Completed Event",
            expected_result=False,
            log={
                "event": "envelope-completed",
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
                    "envelopeSummary": {"status": "completed", "created": "2024-01-15T09:00:00.000Z"},
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
