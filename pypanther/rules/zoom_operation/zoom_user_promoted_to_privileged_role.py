import re

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class ZoomUserPromotedtoPrivilegedRole(Rule):
    default_description = "A Zoom user was promoted to a privileged role."
    display_name = "Zoom User Promoted to Privileged Role"
    default_reference = "https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0064983"
    default_severity = Severity.MEDIUM
    log_types = [LogType.ZOOM_OPERATION]
    id = "Zoom.User.Promoted.to.Privileged.Role-prototype"
    PRIVILEGED_ROLES = ("Admin", "Co-Owner", "Owner", "Billing Admin")

    def extract_values(self, event):
        operator = event.get("operator", "<operator-not-found>")
        operation_detail = event.get("operation_detail", "")
        email = re.search("[\\w.+-c]+@[\\w-]+\\.[\\w.-]+", operation_detail)[0] or "<email-not-found>"
        fromto = re.findall("from ([-\\s\\w]+) to ([-\\s\\w]+)", operation_detail) or [
            ("<from-role-not-found>", "<to-role-not-found>"),
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
        return f"Zoom: [{email}]'s role was changed from [{from_role}] to [{to_role}] by [{operator}]."

    tests = [
        RuleTest(
            name="Admin Promotion Event",
            expected_result=True,
            log={
                "action": "Batch Update",
                "category_type": "User",
                "operation_detail": "Change Role  - homer.simpson@duff.io: from User to Co-Owner",
                "operator": "admin@duff.io",
                "time": "2022-07-05 20:28:48",
            },
        ),
        RuleTest(
            name="Admin to Admin",
            expected_result=False,
            log={
                "action": "Batch Update",
                "category_type": "User",
                "operation_detail": "Change Role  - homer.simpson@duff.io: from Admin to Co-Owner",
                "operator": "admin@duff.io",
                "time": "2022-07-05 20:28:48",
            },
        ),
        RuleTest(
            name="Admin to Billing Admin",
            expected_result=False,
            log={
                "action": "Batch Update",
                "category_type": "User",
                "operation_detail": "Change Role  - homer.simpson@duff.io: from Admin to Billing Admin",
                "operator": "admin@duff.io",
                "time": "2022-07-05 20:28:48",
            },
        ),
        RuleTest(
            name="Member to Billing Admin Event",
            expected_result=True,
            log={
                "action": "Batch Update",
                "category_type": "User",
                "operation_detail": "Change Role  - homer.simpson@duff.io: from Member to Billing Admin",
                "operator": "admin@duff.io",
                "time": "2022-07-05 20:28:48",
            },
        ),
        RuleTest(
            name="Admin to User",
            expected_result=False,
            log={
                "action": "Batch Update",
                "category_type": "User",
                "operation_detail": "Change Role  - homer.simpson@duff.io: from Co-Owner to User",
                "operator": "admin@duff.io",
                "time": "2022-07-05 20:28:48",
            },
        ),
        RuleTest(
            name="CoOwner to Admin",
            expected_result=False,
            log={
                "action": "Batch Update",
                "category_type": "User",
                "operation_detail": "Change Role  - homer.simpson@duff.io: from Co-Owner to Admin",
                "operator": "admin@duff.io",
                "time": "2022-07-05 20:28:48",
            },
        ),
        RuleTest(
            name="Other Event",
            expected_result=False,
            log={
                "action": "SCIM API - Update",
                "category_type": "User",
                "operation_detail": "Edit User homer.simpson@duff.co  - Change Type: from Basic to Licensed",
                "operator": "admin@duff.co",
                "time": "2022-07-01 22:05:22",
            },
        ),
    ]
