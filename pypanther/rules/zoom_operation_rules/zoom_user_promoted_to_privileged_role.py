import re
from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

zoom_user_promotedto_privileged_role_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Admin Promotion Event",
        ExpectedResult=True,
        Log={
            "action": "Batch Update",
            "category_type": "User",
            "operation_detail": "Change Role  - homer.simpson@duff.io: from User to Co-Owner",
            "operator": "admin@duff.io",
            "time": "2022-07-05 20:28:48",
        },
    ),
    PantherRuleTest(
        Name="Admin to Admin",
        ExpectedResult=False,
        Log={
            "action": "Batch Update",
            "category_type": "User",
            "operation_detail": "Change Role  - homer.simpson@duff.io: from Admin to Co-Owner",
            "operator": "admin@duff.io",
            "time": "2022-07-05 20:28:48",
        },
    ),
    PantherRuleTest(
        Name="Admin to Billing Admin",
        ExpectedResult=False,
        Log={
            "action": "Batch Update",
            "category_type": "User",
            "operation_detail": "Change Role  - homer.simpson@duff.io: from Admin to Billing Admin",
            "operator": "admin@duff.io",
            "time": "2022-07-05 20:28:48",
        },
    ),
    PantherRuleTest(
        Name="Member to Billing Admin Event",
        ExpectedResult=True,
        Log={
            "action": "Batch Update",
            "category_type": "User",
            "operation_detail": "Change Role  - homer.simpson@duff.io: from Member to Billing Admin",
            "operator": "admin@duff.io",
            "time": "2022-07-05 20:28:48",
        },
    ),
    PantherRuleTest(
        Name="Admin to User",
        ExpectedResult=False,
        Log={
            "action": "Batch Update",
            "category_type": "User",
            "operation_detail": "Change Role  - homer.simpson@duff.io: from Co-Owner to User",
            "operator": "admin@duff.io",
            "time": "2022-07-05 20:28:48",
        },
    ),
    PantherRuleTest(
        Name="CoOwner to Admin",
        ExpectedResult=False,
        Log={
            "action": "Batch Update",
            "category_type": "User",
            "operation_detail": "Change Role  - homer.simpson@duff.io: from Co-Owner to Admin",
            "operator": "admin@duff.io",
            "time": "2022-07-05 20:28:48",
        },
    ),
    PantherRuleTest(
        Name="Other Event",
        ExpectedResult=False,
        Log={
            "action": "SCIM API - Update",
            "category_type": "User",
            "operation_detail": "Edit User homer.simpson@duff.co  - Change Type: from Basic to Licensed",
            "operator": "admin@duff.co",
            "time": "2022-07-01 22:05:22",
        },
    ),
]


class ZoomUserPromotedtoPrivilegedRole(PantherRule):
    Description = "A Zoom user was promoted to a privileged role."
    DisplayName = "Zoom User Promoted to Privileged Role"
    Reference = "https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0064983"
    Severity = PantherSeverity.Medium
    LogTypes = [LogType.Zoom_Operation]
    RuleID = "Zoom.User.Promoted.to.Privileged.Role-prototype"
    Tests = zoom_user_promotedto_privileged_role_tests
    PRIVILEGED_ROLES = ("Admin", "Co-Owner", "Owner", "Billing Admin")

    def extract_values(self, event):
        operator = event.get("operator", "<operator-not-found>")
        operation_detail = event.get("operation_detail", "")
        email = (
            re.search("[\\w.+-c]+@[\\w-]+\\.[\\w.-]+", operation_detail)[0] or "<email-not-found>"
        )
        fromto = re.findall("from ([-\\s\\w]+) to ([-\\s\\w]+)", operation_detail) or [
            ("<from-role-not-found>", "<to-role-not-found>")
        ]
        from_role, to_role = fromto[0] or ("<role-not-found>", "<role-not-found>")
        return (operator, email, from_role, to_role)

    def rule(self, event):
        if (
            "Update" in event.get("action", "")
            and event.get("category_type") == "User"
            and event.get("operation_detail", "").startswith("Change Role")
        ):
            _, _, from_role, to_role = self.extract_values(event)
            return to_role in self.PRIVILEGED_ROLES and from_role not in self.PRIVILEGED_ROLES
        return False

    def title(self, event):
        operator, email, from_role, to_role = self.extract_values(event)
        return (
            f"Zoom: [{email}]'s role was changed from [{from_role}] to [{to_role}] by [{operator}]."
        )
