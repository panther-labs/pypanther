from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class BoxContentWorkflowPolicyViolation(Rule):
    id = "Box.Content.Workflow.Policy.Violation-prototype"
    display_name = "Box Content Workflow Policy Violation"
    log_types = [LogType.BOX_EVENT]
    tags = ["Box"]
    default_severity = Severity.LOW
    default_description = "A user violated the content workflow policy.\n"
    default_reference = "https://support.box.com/hc/en-us/articles/360043692594-Creating-a-Security-Policy"
    default_runbook = "Investigate whether the user continues to violate the policy and take measure to ensure they understand policy.\n"
    summary_attributes = ["event_type"]
    POLICY_VIOLATIONS = {"CONTENT_WORKFLOW_UPLOAD_POLICY_VIOLATION", "CONTENT_WORKFLOW_SHARING_POLICY_VIOLATION"}

    def rule(self, event):
        return event.get("event_type") in self.POLICY_VIOLATIONS

    def title(self, event):
        return f"User [{event.deep_get('created_by', 'name', default='<UNKNOWN_USER>')}] violated a content workflow policy."

    tests = [
        RuleTest(
            name="Regular Event",
            expected_result=False,
            log={
                "type": "event",
                "additional_details": '{"key": "value"}',
                "created_by": {"id": "12345678", "type": "user", "login": "cat@example", "name": "Bob Cat"},
                "event_type": "DELETE",
            },
        ),
        RuleTest(
            name="Upload Policy Violation",
            expected_result=True,
            log={
                "type": "event",
                "additional_details": '{"key": "value"}',
                "created_by": {"id": "12345678", "type": "user", "login": "cat@example", "name": "Bob Cat"},
                "event_type": "CONTENT_WORKFLOW_UPLOAD_POLICY_VIOLATION",
                "source": {"id": "12345678", "type": "user", "login": "user@example"},
            },
        ),
        RuleTest(
            name="Sharing Policy Violation",
            expected_result=True,
            log={
                "type": "event",
                "additional_details": {"key": "value"},
                "created_by": {"id": "12345678", "type": "user", "login": "cat@example", "name": "Mountain Lion"},
                "event_type": "CONTENT_WORKFLOW_SHARING_POLICY_VIOLATION",
                "source": {"id": "12345678", "type": "user", "login": "user@example"},
            },
        ),
    ]
