from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_snyk_helpers import snyk_alert_context
from pypanther.log_types import LogType

snyk_role_change_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Snyk Group Role Edit -  ADMIN role ( CRIT )",
        ExpectedResult=True,
        Log={
            "content": {
                "after": {"role": "ADMIN", "rolePublicId": "8ddddddd-fbbb-4fff-8111-5eeeeeeeeeee"},
                "before": {
                    "role": "MEMBER",
                    "rolePublicId": "6aaaaaaa-c000-4ddd-9ddd-c55555555555",
                },
                "userPublicId": "05555555-3333-4ddd-8ccc-755555555555",
            },
            "created": "1999-04-04 18:38:19.843",
            "event": "group.user.role.edit",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "userId": "05555555-3333-4ddd-8ccc-755555555555",
        },
    ),
    PantherRuleTest(
        Name="Snyk Org Role Edit -  ADMIN role ( CRIT )",
        ExpectedResult=True,
        Log={
            "content": {
                "afterRoleName": "ADMIN",
                "afterRolePublicId": "d8999999-aaaa-4999-9f0b-9bbbbbbbbbbb",
                "beforeRoleName": "Org Collaborator",
                "beforeRolePublicId": "b0000000-dbbb-4000-addd-1ddddddddddd",
                "userPublicId": "05555555-3333-4ddd-8ccc-755555555555",
            },
            "created": "1999-03-08 16:24:02.616",
            "event": "org.user.role.edit",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "userId": "05555555-3333-4ddd-8ccc-755555555555",
            "orgId": "21111111-a222-4eee-8ddd-a99999999999",
        },
    ),
    PantherRuleTest(
        Name="Snyk Group Role Edit -  MEMBER role ( MEDIUM )",
        ExpectedResult=True,
        Log={
            "content": {
                "before": {"role": "ADMIN", "rolePublicId": "8ddddddd-fbbb-4fff-8111-5eeeeeeeeeee"},
                "after": {"role": "MEMBER", "rolePublicId": "6aaaaaaa-c000-4ddd-9ddd-c55555555555"},
                "userPublicId": "05555555-3333-4ddd-8ccc-755555555555",
            },
            "created": "1999-04-04 18:38:19.843",
            "event": "group.user.role.edit",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "userId": "05555555-3333-4ddd-8ccc-755555555555",
        },
    ),
    PantherRuleTest(
        Name="Snyk Group SSO Membership sync",
        ExpectedResult=False,
        Log={
            "content": {},
            "created": "2023-03-15 13:13:13.133",
            "event": "group.sso.membership.sync",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
        },
    ),
]


class SnykRoleChange(PantherRule):
    RuleID = "Snyk.Role.Change-prototype"
    DisplayName = "Snyk Role Change"
    LogTypes = [LogType.Snyk_GroupAudit, LogType.Snyk_OrgAudit]
    Tags = ["Snyk"]
    Severity = PantherSeverity.High
    Description = "Detects when Snyk Roles are changed\n"
    Runbook = "These actions in the Snyk Audit logs indicate that a ServiceAccount has been created/deleted/modified.\nAll events where the Role is marked as ADMIN have CRITICAL severity Other events are marked with MEDIUM severity\n"
    Reference = "https://docs.snyk.io/snyk-admin/manage-users-and-permissions/member-roles"
    SummaryAttributes = ["event"]
    Tests = snyk_role_change_tests
    ACTIONS = [
        "group.role.create",
        "group.role.edit",
        "group.user.role.create",
        "group.user.role.delete",
        "group.user.role.edit",
        "org.user.role.create",
        "org.user.role.delete",
        "org.user.role.details.edit",
        "org.user.role.edit",
        "org.user.role.permissions.edit",
    ]

    def rule(self, event):
        action = deep_get(event, "event", default="<NO_EVENT>")
        return action in self.ACTIONS

    def title(self, event):
        group_or_org = "<GROUP_OR_ORG>"
        crud_operation = "<NO_OPERATION>"
        action = deep_get(event, "event", default="<NO_EVENT>")
        if "." in action:
            group_or_org = action.split(".")[0].title()
            crud_operation = action.split(".")[-1].title()
        return f"Snyk: [{group_or_org}] Role [{crud_operation}] performed by [{deep_get(event, 'userId', default='<NO_USERID>')}]"

    def alert_context(self, event):
        a_c = snyk_alert_context(event)
        role = deep_get(event, "content", "after", "role", default=None)
        if not role and "afterRoleName" in deep_get(event, "content", default={}):
            role = deep_get(event, "content", "afterRoleName", default=None)
        if role:
            a_c["role_permission"] = role
        return a_c

    def dedup(self, event):
        return f"{deep_get(event, 'userId', default='<NO_USERID>')}{deep_get(event, 'orgId', default='<NO_ORGID>')}{deep_get(event, 'groupId', default='<NO_GROUPID>')}{deep_get(event, 'event', default='<NO_EVENT>')}"

    def severity(self, event):
        role = deep_get(event, "content", "after", "role", default=None)
        if not role and "afterRoleName" in deep_get(event, "content", default={}):
            role = deep_get(event, "content", "afterRoleName", default=None)
        if role == "ADMIN":
            return "CRITICAL"
        return "MEDIUM"
