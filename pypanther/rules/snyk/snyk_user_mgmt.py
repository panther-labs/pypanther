from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.snyk import snyk_alert_context


@panther_managed
class SnykUserManagement(Rule):
    id = "Snyk.User.Management-prototype"
    display_name = "Snyk User Management"
    log_types = [LogType.SNYK_GROUP_AUDIT, LogType.SNYK_ORG_AUDIT]
    tags = ["Snyk"]
    default_severity = Severity.MEDIUM
    default_description = "Detects when Snyk Users are changed\n"
    default_runbook = "These actions in the Snyk Audit logs indicate that a User has been created/deleted/modified.\n"
    default_reference = "https://docs.snyk.io/snyk-admin/manage-users-and-permissions/member-roles"
    summary_attributes = ["event"]
    ACTIONS = [
        "group.user.add",
        "group.user.provision.accept",
        "group.user.provision.create",
        "group.user.provision.delete",
        "group.user.remove",
        "org.user.add",
        "org.user.invite",
        "org.user.invite.accept",
        "org.user.invite.revoke",
        "org.user.invite_link.accept",
        "org.user.invite_link.create",
        "org.user.invite_link.revoke",
        "org.user.leave",
        "org.user.provision.accept",
        "org.user.provision.create",
        "org.user.provision.delete",
        "org.user.remove",
    ]

    def rule(self, event):
        action = event.get("event", "<NO_EVENT>")
        # for org.user.add/group.user.add via SAML/SCIM
        # the attributes .userId and .content.publicUserId
        # have the same value
        if action.endswith(".user.add"):
            target_user = event.deep_get("content", "userPublicId", default="<NO_CONTENT_UID>")
            actor = event.get("userId", "<NO_USERID>")
            if target_user == actor:
                return False
        return action in self.ACTIONS

    def title(self, event):
        group_or_org = "<GROUP_OR_ORG>"
        operation = "<NO_OPERATION>"
        action = event.get("event", "<NO_EVENT>")
        if "." in action:
            group_or_org = action.split(".")[0].title()
            operation = ".".join(action.split(".")[2:]).title()
        return f"Snyk: [{group_or_org}] User [{operation}] performed by [{event.deep_get('userId', default='<NO_USERID>')}]"

    def alert_context(self, event):
        return snyk_alert_context(event)

    def dedup(self, event):
        return f"{event.deep_get('userId', default='<NO_USERID>')}{event.deep_get('orgId', default='<NO_ORGID>')}{event.deep_get('groupId', default='<NO_GROUPID>')}{event.deep_get('event', default='<NO_EVENT>')}"

    def severity(self, event):
        role = event.deep_get("content", "after", "role", default=None)
        if not role and "afterRoleName" in event.get("content", {}):
            role = event.deep_get("content", "afterRoleName", default=None)
        if role == "ADMIN":
            return "CRITICAL"
        return "MEDIUM"

    tests = [
        RuleTest(
            name="Snyk User Removed",
            expected_result=True,
            log={
                "content": {
                    "email": "user@example.com",
                    "force": True,
                    "name": "user@example.com",
                    "userPublicId": "cccccccc-3333-4ddd-8ccc-755555555555",
                    "username": "user@example.com",
                },
                "created": "2023-04-11 23:32:14.173",
                "event": "org.user.remove",
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "orgId": "21111111-a222-4eee-8ddd-a99999999999",
                "userId": "05555555-3333-4ddd-8ccc-755555555555",
            },
        ),
        RuleTest(
            name="Snyk User Invite Revoke",
            expected_result=True,
            log={
                "content": {},
                "created": "2023-04-11 23:32:13.248",
                "event": "org.user.invite.revoke",
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "orgId": "21111111-a222-4eee-8ddd-a99999999999",
                "userId": "05555555-3333-4ddd-8ccc-755555555555",
            },
        ),
        RuleTest(
            name="Snyk Group User add",
            expected_result=True,
            log={
                "content": {
                    "role": "Group Member",
                    "rolePublicId": "65555555-c000-4ddd-2222-cfffffffffff",
                    "userPublicId": "cccccccc-3333-4ddd-8ccc-755555555555",
                },
                "created": "2023-04-11 23:14:55.572",
                "event": "group.user.add",
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "userId": "05555555-3333-4ddd-8ccc-755555555555",
            },
        ),
        RuleTest(
            name="Snyk System SSO Setting event happened",
            expected_result=False,
            log={
                "userId": "05555555-3333-4ddd-8ccc-755555555555",
                "event": "group.sso.edit",
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "orgId": "21111111-a222-4eee-8ddd-a99999999999",
                "content": {"unknown": "contents"},
            },
        ),
        RuleTest(
            name="SAML User Added",
            expected_result=False,
            log={
                "content": {
                    "role": "Org Collaborator",
                    "rolePublicId": "beeeeeee-dddd-4444-aaaa-133333333333",
                    "userPublicId": "05555555-3333-4ddd-8ccc-755555555555",
                },
                "created": "2023-06-01 03:14:42.776",
                "event": "org.user.add",
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "orgId": "21111111-a222-4eee-8ddd-a99999999999",
                "userId": "05555555-3333-4ddd-8ccc-755555555555",
            },
        ),
    ]
