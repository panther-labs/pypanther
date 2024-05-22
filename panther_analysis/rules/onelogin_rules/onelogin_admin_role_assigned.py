from typing import List
from panther_analysis.base import PantherRule, PantherRuleTest, Severity

one_login_admin_role_assigned_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Non permissions assigned event", ExpectedResult=False, Log={"event_type_id": "8"}
    ),
    PantherRuleTest(
        Name="Non super user permissions assigned",
        ExpectedResult=False,
        Log={"event_type_id": "72", "privilege_name": "Manage users"},
    ),
    PantherRuleTest(
        Name="Super user permissions assigned",
        ExpectedResult=True,
        Log={
            "event_type_id": "72",
            "privilege_name": "Super user",
            "user_name": "Evil Bob",
            "actor_user_name": "Bobert O'Bobly",
        },
    ),
]


class OneLoginAdminRoleAssigned(PantherRule):
    RuleID = "OneLogin.AdminRoleAssigned-prototype"
    DisplayName = "--DEPRECATED-- OneLogin Admin Role Assigned"
    Enabled = False
    LogTypes = ["OneLogin.Events"]
    Tags = ["Identity & Access Management"]
    Reference = "https://onelogin.service-now.com/kb_view_customer.do?sysparm_article=KB0010391"
    Severity = Severity.Low
    SummaryAttributes = ["account_id", "user_name", "user_id", "privilege_name"]
    Tests = one_login_admin_role_assigned_tests

    def rule(self, event):
        # event_type_id 72 is permissions assigned
        return (
            str(event.get("event_type_id")) == "72" and event.get("privilege_name") == "Super user"
        )

    def title(self, event):
        # (Optional) Return a string which will be shown as the alert title.
        return f"[{event.get('actor_user_name', '<UNKNOWN_USER>')}] assigned super user permissions to [{event.get('user_name', '<UNKNOWN_USER>')}]"
