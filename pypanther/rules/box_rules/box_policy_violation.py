from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

box_content_workflow_policy_violation_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Regular Event",
        ExpectedResult=False,
        Log={
            "type": "event",
            "additional_details": '{"key": "value"}',
            "created_by": {
                "id": "12345678",
                "type": "user",
                "login": "cat@example",
                "name": "Bob Cat",
            },
            "event_type": "DELETE",
        },
    ),
    PantherRuleTest(
        Name="Upload Policy Violation",
        ExpectedResult=True,
        Log={
            "type": "event",
            "additional_details": '{"key": "value"}',
            "created_by": {
                "id": "12345678",
                "type": "user",
                "login": "cat@example",
                "name": "Bob Cat",
            },
            "event_type": "CONTENT_WORKFLOW_UPLOAD_POLICY_VIOLATION",
            "source": {"id": "12345678", "type": "user", "login": "user@example"},
        },
    ),
    PantherRuleTest(
        Name="Sharing Policy Violation",
        ExpectedResult=True,
        Log={
            "type": "event",
            "additional_details": {"key": "value"},
            "created_by": {
                "id": "12345678",
                "type": "user",
                "login": "cat@example",
                "name": "Mountain Lion",
            },
            "event_type": "CONTENT_WORKFLOW_SHARING_POLICY_VIOLATION",
            "source": {"id": "12345678", "type": "user", "login": "user@example"},
        },
    ),
]


class BoxContentWorkflowPolicyViolation(PantherRule):
    RuleID = "Box.Content.Workflow.Policy.Violation-prototype"
    DisplayName = "Box Content Workflow Policy Violation"
    LogTypes = [LogType.Box_Event]
    Tags = ["Box"]
    Severity = PantherSeverity.Low
    Description = "A user violated the content workflow policy.\n"
    Reference = "https://support.box.com/hc/en-us/articles/360043692594-Creating-a-Security-Policy"
    Runbook = "Investigate whether the user continues to violate the policy and take measure to ensure they understand policy.\n"
    SummaryAttributes = ["event_type"]
    Tests = box_content_workflow_policy_violation_tests
    POLICY_VIOLATIONS = {
        "CONTENT_WORKFLOW_UPLOAD_POLICY_VIOLATION",
        "CONTENT_WORKFLOW_SHARING_POLICY_VIOLATION",
    }

    def rule(self, event):
        return event.get("event_type") in self.POLICY_VIOLATIONS

    def title(self, event):
        return f"User [{deep_get(event, 'created_by', 'name', default='<UNKNOWN_USER>')}] violated a content workflow policy."
