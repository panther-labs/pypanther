from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.snyk import snyk_alert_context


@panther_managed
class SnykServiceAccountChange(Rule):
    id = "Snyk.ServiceAccount.Change-prototype"
    display_name = "Snyk Service Account Change"
    log_types = [LogType.SNYK_GROUP_AUDIT, LogType.SNYK_ORG_AUDIT]
    tags = ["Snyk"]
    default_severity = Severity.HIGH
    default_description = "Detects when Snyk Service Accounts are changed\n"
    default_runbook = "These actions in the Snyk Audit logs indicate that a ServiceAccount has been created/deleted/modified.\nService Accounts are system user accounts with an API token associated to it in place of standard user credentials. All events where the Service Account's role is ADMIN have CRITICAL severity Deletion events are marked with HIGH severity Creation events are marked with HIGH severity Edit events are marked with MEDIUM Severity\n"
    default_reference = "https://docs.snyk.io/snyk-admin/service-accounts"
    summary_attributes = ["event"]
    ACTIONS = [
        "group.service_account.create",
        "group.service_account.delete",
        "group.service_account.edit",
        "org.service_account.create",
        "org.service_account.delete",
        "org.service_account.edit",
        "org.service_account.membership.upsert",
    ]

    def rule(self, event):
        action = event.get("event", "<NO_EVENT>")
        return action in self.ACTIONS

    def title(self, event):
        group_or_org = "<GROUP_OR_ORG>"
        crud_operation = "<NO_OPERATION>"
        action = event.get("event", "<NO_EVENT>")
        if "." in action:
            group_or_org = action.split(".")[0].title()
            crud_operation = action.split(".")[-1].title()
        return f"Snyk: [{group_or_org}] Service Account [{crud_operation}] performed by [{event.deep_get('userId', default='<NO_USERID>')}]"

    def alert_context(self, event):
        a_c = snyk_alert_context(event)
        role = event.deep_get("content", "role", "role", default=None)
        if not role:
            role = event.deep_get("content", "role", default=None)
        if role:
            a_c["role_permission"] = role
        return a_c

    def dedup(self, event):
        return f"{event.deep_get('userId', default='<NO_USERID>')}{event.deep_get('orgId', default='<NO_ORGID>')}{event.deep_get('groupId', default='<NO_GROUPID>')}{event.deep_get('event', default='<NO_EVENT>')}"

    def severity(self, event):
        action = event.get("event", "<NO_EVENT>")
        role = event.deep_get("content", "role", "role", default=None)
        if not role:
            role = event.deep_get("content", "role", default=None)
        if all([role == "ADMIN", action.endswith((".service_account.create", ".service_account.delete"))]):
            return "CRITICAL"
        if action.endswith((".service_account.create", ".service_account.delete")):
            return "HIGH"
        return "MEDIUM"

    tests = [
        RuleTest(
            name="Snyk Org Service Account ADMIN role ( CRIT )",
            expected_result=True,
            log={
                "content": {
                    "role": "ADMIN",
                    "rolePublicId": "d8999999-aaaa-4444-9fff-955555555555",
                    "serviceAccountPublicId": "9ddddddd-4444-4111-9eee-188888888888",
                },
                "created": "2023-04-05 22:22:57.488",
                "event": "org.service_account.create",
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "orgId": "21111111-a222-4eee-8ddd-a99999999999",
                "userId": "05555555-3333-4ddd-8ccc-755555555555",
            },
        ),
        RuleTest(
            name="Snyk Group Service Account ADMIN role ( CRIT )",
            expected_result=True,
            log={
                "content": {
                    "role": {
                        "created": "1999-01-22T16:02:53.848Z",
                        "description": "Admin",
                        "groupPermissions": [
                            "group.read",
                            "group.edit",
                            "group.iac.settings.read",
                            "group.iac.settings.edit",
                            "group.report.read",
                            "group.org.add",
                            "group.org.remove",
                            "group.org.list",
                            "group.user.add",
                            "group.user.read",
                            "group.user.remove",
                            "group.user.delete",
                            "group.user.role.edit",
                            "group.user.provision",
                            "group.service_account.create",
                            "group.service_account.read",
                            "group.service_account.edit",
                            "group.service_account.delete",
                            "group.audit.read",
                            "group.settings.read",
                            "group.settings.edit",
                            "group.notification_settings.read",
                            "group.notification_settings.edit",
                            "group.policy.read",
                            "group.policy.create",
                            "group.policy.edit",
                            "group.policy.delete",
                            "group.tag.read",
                            "group.tag.create",
                            "group.tag.delete",
                            "group.flags.read",
                            "group.flags.edit",
                            "group.settings.request_access.read",
                            "group.settings.request_access.edit",
                            "group.sso.read",
                            "group.sso.edit",
                            "group.sso.remove",
                            "group.roles.read",
                            "group.roles.create",
                            "group.roles.edit",
                            "group.roles.remove",
                        ],
                        "id": 1,
                        "modified": "1999-01-07T12:36:51.716Z",
                        "name": "Group Admin",
                        "orgPermissions": [
                            "org.read",
                            "org.create",
                            "org.edit",
                            "org.delete",
                            "org.report.read",
                            "org.project.create",
                            "org.project.read",
                            "org.project.edit",
                            "org.project.delete",
                            "org.project.status",
                            "org.project.test",
                            "org.project.move",
                            "org.project.integration.edit",
                            "org.project.jira.issue.read",
                            "org.project.jira.issue.create",
                            "org.project.ignore.create",
                            "org.project.ignore.read",
                            "org.project.ignore.edit",
                            "org.project.ignore.delete",
                            "org.project.pr.create",
                            "org.project.pr.skip",
                            "org.project.attributes.edit",
                            "org.project.tag.edit",
                            "org.service_account.create",
                            "org.service_account.read",
                            "org.service_account.edit",
                            "org.service_account.delete",
                            "org.user.add",
                            "org.user.invite",
                            "org.user.manage",
                            "org.user.read",
                            "org.user.delete",
                            "org.user.leave",
                            "org.user.provision",
                            "org.integration.read",
                            "org.integration.edit",
                            "org.package.test",
                            "org.billing.read",
                            "org.billing.edit",
                            "org.entitlements.read",
                            "org.audit_log.read",
                            "org.flags.read",
                            "org.flags.edit",
                            "org.outbound_webhook.read",
                            "org.outbound_webhook.create",
                            "org.outbound_webhook.delete",
                            "org.app.read",
                            "org.app.install",
                            "org.app.create",
                            "org.app.delete",
                            "org.app.edit",
                            "org.cloud_environments.read",
                            "org.cloud_environments.create",
                            "org.cloud_environments.delete",
                            "org.cloud_environments.edit",
                            "org.cloud_scans.read",
                            "org.cloud_scans.create",
                            "org.cloud_resources.read",
                            "org.cloud_artifacts.read",
                            "org.cloud_artifacts.create",
                            "org.cloud_custom_rules.read",
                            "org.cloud_custom_rules.create",
                            "org.cloud_custom_rules.edit",
                            "org.cloud_custom_rules.delete",
                        ],
                        "publicId": "89999999-feee-4333-8ccc-5aaaaaaaaaaa",
                        "role": "ADMIN",
                        "userPermissions": ["user.activate", "user.deactivate"],
                    },
                    "serviceAccountPublicId": "98888888-1ccc-4aaa-9fff-d66666666666",
                },
                "created": "2021-02-09 17:46:16.622",
                "event": "group.service_account.create",
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "userId": "05555555-3333-4ddd-8ccc-755555555555",
            },
        ),
        RuleTest(
            name="Snyk Group Service Account Create - Viewer Role ( HIGH )",
            expected_result=True,
            log={
                "content": {
                    "role": {
                        "created": "1999-01-22T16:02:53.848Z",
                        "description": "Viewer",
                        "groupPermissions": ["group.tag.read"],
                        "id": 3,
                        "modified": "1999-02-01T12:36:51.728Z",
                        "name": "Group Viewer",
                        "orgPermissions": ["org.read"],
                        "publicId": "24444444-addd-4ddd-a444-0ddddddddddd",
                        "role": "VIEWER",
                        "userPermissions": [],
                    },
                    "serviceAccountPublicId": "06666666-9eee-4ccc-8999-4bbbbbbbbbbb",
                },
                "created": "2021-01-08 17:13:01.355",
                "event": "group.service_account.create",
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "userId": "05555555-3333-4ddd-8ccc-755555555555",
            },
        ),
        RuleTest(
            name="Snyk Service Account Edit ( MEDIUM )",
            expected_result=True,
            log={
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "userId": "05555555-3333-4ddd-8ccc-755555555555",
                "event": "group.service_account.edit",
                "content": {
                    "after": {"name": "test-SA-after"},
                    "before": {"name": "test-SA-before"},
                    "serviceAccountPublicId": "41111111-3fff-4eee-b111-6bbbbbbbbbbb",
                },
                "created": "2023-02-12T23:57:35.522Z",
            },
        ),
        RuleTest(
            name="Snyk Group SSO Membership sync",
            expected_result=False,
            log={
                "content": {},
                "created": "2023-03-15 13:13:13.133",
                "event": "group.sso.membership.sync",
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
            },
        ),
    ]
