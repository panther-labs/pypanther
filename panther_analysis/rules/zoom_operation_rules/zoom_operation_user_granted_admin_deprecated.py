from typing import List
from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_zoom_helpers import get_zoom_user_context as get_context

zoom_user_granted_admin_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="User Granted Admin",
        ExpectedResult=True,
        Log={
            "operator": "homer@panther.io",
            "category_type": "User",
            "action": "Update",
            "operation_detail": "Update User bart@panther.io  - User Role: from Member to Admin",
        },
    ),
    PantherRuleTest(
        Name="Non-admin user update",
        ExpectedResult=False,
        Log={
            "operator": "homer@panther.io",
            "category_type": "User",
            "action": "Update",
            "operation_detail": "Update User lisa@panther.io  - Job Title: set to Contractor",
        },
    ),
]


class ZoomUserGrantedAdmin(PantherRule):
    RuleID = "Zoom.UserGrantedAdmin-prototype"
    DisplayName = "--DEPRECATED -- Zoom User Granted Admin Rights"
    Enabled = False
    LogTypes = ["Zoom.Operation"]
    Tags = ["Zoom", "Privilege Escalation:Valid Accounts"]
    Severity = Severity.Medium
    Description = "A Zoom user has been granted admin access\n"
    Reports = {"MITRE ATT&CK": ["TA0004:T1078"]}
    Reference = "https://support.zoom.us/hc/en-us/articles/115001078646-Using-role-management"
    Runbook = "Contact Zoom admin and ensure this access level is intended and appropriate\n"
    SummaryAttributes = ["p_any_emails"]
    Tests = zoom_user_granted_admin_tests

    def rule(self, event):
        if event.get("Action") != "Update" or event.get("category_type") != "User":
            return False
        context = get_context(event)
        return "Member to Admin" in context["Change"]

    def title(self, event):
        context = get_context(event)
        return f"Zoom User {context['User']} was made an admin by {event.get('operator')}"
