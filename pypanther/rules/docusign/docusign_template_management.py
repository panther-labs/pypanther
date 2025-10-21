from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.docusign import docusign_alert_context


@panther_managed
class DocusignConnectTemplateManagement(Rule):
    id = "Docusign.Connect.TemplateManagement-prototype"
    display_name = "DocuSign Template Management Activity"
    log_types = [LogType.DOCUSIGN_CONNECT]
    tags = ["DocuSign", "Template", "Administrative"]
    default_severity = Severity.MEDIUM
    default_description = "Detects DocuSign template management activities including creation, modification, and deletion. Template changes can affect business processes and should be monitored for unauthorized modifications. Deletions are particularly critical as they may indicate data destruction or process disruption.\n"
    default_runbook = "1. Review the template changes and verify they are authorized\n2. Check if the user has appropriate permissions for template management\n3. For deletions, verify if this was intentional and documented\n4. For modifications, review what specific changes were made\n5. Monitor for patterns of excessive template changes\n6. Ensure proper approval workflow was followed for template changes\n"
    default_reference = "https://developer.docusign.com/docs/connect/events/"
    summary_attributes = ["event", "data.templateId", "data.userId", "data.email"]

    def rule(self, event):
        template_events = ["template-created", "template-modified", "template-deleted"]
        return event.get("event") in template_events

    def title(self, event):
        event_type = event.get("event", "template-modified").split("-")[1]
        template_id = event.deep_get("data", "templateId", default="Unknown")
        user_id = event.deep_get("data", "userId", default="Unknown")
        action = event_type.replace("template-", "").replace("-", " ").title()
        return f"DocuSign template {action.lower()}: {template_id} by user {user_id}"

    def severity(self, event):
        event_type = event.get("event")
        if event_type == "template-deleted":
            return "DEFAULT"
        if event_type == "template-modified":
            return "LOW"
        return "INFO"

    def alert_context(self, event):
        return docusign_alert_context(event)

    tests = [
        RuleTest(
            name="Template Created Event",
            expected_result=True,
            log={
                "event": "template-created",
                "uri": "/api/v2/accounts/12345/templates/template123",
                "retryCount": 0,
                "configurationId": "config123",
                "apiVersion": "v2.1",
                "generatedDateTime": "2024-01-15T10:30:00.000Z",
                "data": {
                    "accountId": "12345",
                    "userId": "user123",
                    "templateId": "template123",
                    "name": "Contract Template",
                    "email": "peregrin@lotr.com",
                    "templates": [{"templateId": "template123", "name": "Contract Template", "shared": True}],
                },
            },
        ),
        RuleTest(
            name="Template Modified Event",
            expected_result=True,
            log={
                "event": "template-modified",
                "uri": "/api/v2/accounts/12345/templates/template123",
                "retryCount": 0,
                "configurationId": "config123",
                "apiVersion": "v2.1",
                "generatedDateTime": "2024-01-15T10:30:00.000Z",
                "data": {
                    "accountId": "12345",
                    "userId": "user123",
                    "templateId": "template123",
                    "name": "Updated Contract Template",
                    "email": "admin@example.com",
                },
            },
        ),
        RuleTest(
            name="Template Deleted Event",
            expected_result=True,
            log={
                "event": "template-deleted",
                "uri": "/api/v2/accounts/12345/templates/template123",
                "retryCount": 0,
                "configurationId": "config123",
                "apiVersion": "v2.1",
                "generatedDateTime": "2024-01-15T10:30:00.000Z",
                "data": {
                    "accountId": "12345",
                    "userId": "user123",
                    "templateId": "template123",
                    "name": "Contract Template",
                    "email": "admin@example.com",
                },
            },
        ),
        RuleTest(
            name="Non-Template Event",
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
