from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers import event_type


@panther_managed
class StandardAdminRoleAssigned(Rule):
    id = "Standard.AdminRoleAssigned-prototype"
    display_name = "Admin Role Assigned"
    log_types = [
        LogType.ASANA_AUDIT,
        LogType.ATLASSIAN_AUDIT,
        LogType.GCP_AUDIT_LOG,
        LogType.GITHUB_AUDIT,
        LogType.GSUITE_REPORTS,
        LogType.ONELOGIN_EVENTS,
        LogType.ZENDESK_AUDIT,
    ]
    tags = ["DataModel", "Privilege Escalation:Valid Accounts"]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0004:T1078"]}
    default_description = "Assigning an admin role manually could be a sign of privilege escalation"
    default_runbook = "Verify with the user who attached the role or add to a allowlist"
    default_reference = "https://medium.com/@gokulelango1040/privilege-escalation-attacks-28a9ef226abb"
    summary_attributes = ["p_any_ip_addresses"]

    def rule(self, event):
        # filter events on unified data model field
        return event.udm("event_type") == event_type.ADMIN_ROLE_ASSIGNED

    def title(self, event):
        # use unified data model field in title
        return f"{event.get('p_log_type')}: [{event.udm('actor_user')}] assigned admin privileges [{event.udm('assigned_admin_role')}] to [{event.udm('user')}]"

    def alert_context(self, event):
        return {"ips": event.get("p_any_ip_addresses", []), "actor": event.udm("actor_user"), "user": event.udm("user")}

    tests = [
        RuleTest(
            name="GCP - Admin Assigned",
            expected_result=True,
            log={
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "cloudresourcemanager.googleapis.com",
                    "methodName": "SetIamPolicy",
                    "authenticationInfo": {"principalEmail": "bob@example.com"},
                    "requestMetadata": {"callerIP": "4.4.4.4"},
                    "serviceData": {
                        "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
                        "policyDelta": {
                            "bindingDeltas": [
                                {
                                    "action": "ADD",
                                    "member": "cat@example.com",
                                    "role": "roles/resourcemanager.organizationAdmin",
                                },
                            ],
                        },
                    },
                },
                "p_log_type": "GCP.AuditLog",
            },
        ),
        RuleTest(
            name="GCP - Multiple Admin Roles Assigned",
            expected_result=True,
            log={
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "cloudresourcemanager.googleapis.com",
                    "methodName": "SetIamPolicy",
                    "authenticationInfo": {"principalEmail": "bob@example.com"},
                    "requestMetadata": {"callerIP": "4.4.4.4"},
                    "serviceData": {
                        "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
                        "policyDelta": {
                            "bindingDeltas": [
                                {
                                    "action": "ADD",
                                    "member": "cat@example.com",
                                    "role": "roles/resourcemanager.organizationAdmin",
                                },
                                {"action": "ADD", "member": "dog@example.com", "role": "roles/owner"},
                            ],
                        },
                    },
                },
                "p_log_type": "GCP.AuditLog",
            },
        ),
        RuleTest(
            name="GSuite - Other Admin Action",
            expected_result=False,
            log={
                "actor": {"email": "bobert@example.com"},
                "id": {"applicationName": "admin"},
                "events": [{"type": "DELEGATED_ADMIN_SETTINGS", "name": "RENAME_ROLE"}],
                "p_log_type": "GSuite.Reports",
            },
        ),
        RuleTest(
            name="GSuite - Privileges Assigned",
            expected_result=True,
            log={
                "actor": {"email": "bobert@example.com"},
                "id": {"applicationName": "admin"},
                "events": [
                    {
                        "type": "DELEGATED_ADMIN_SETTINGS",
                        "name": "ASSIGN_ROLE",
                        "parameters": [
                            {"name": "ROLE_NAME", "value": "Some Admin Role"},
                            {"name": "USER_EMAIL", "value": "bob@example.com"},
                        ],
                    },
                ],
                "p_log_type": "GSuite.Reports",
            },
        ),
        RuleTest(
            name="OneLogin - Non permissions assigned event",
            expected_result=False,
            log={"event_type_id": 8, "p_log_type": "OneLogin.Events"},
        ),
        RuleTest(
            name="OneLogin - Non super user permissions assigned",
            expected_result=False,
            log={"event_type_id": 72, "privilege_name": "Manage users", "p_log_type": "OneLogin.Events"},
        ),
        RuleTest(
            name="OneLogin - Super user permissions assigned",
            expected_result=True,
            log={
                "event_type_id": 72,
                "privilege_name": "Super user",
                "user_name": "Evil Bob",
                "actor_user_name": "Bobert O'Bobly",
                "p_log_type": "OneLogin.Events",
            },
        ),
        RuleTest(
            name="Github - User Promoted",
            expected_result=True,
            log={"actor": "cat", "action": "team.promote_maintainer", "p_log_type": "GitHub.Audit", "user": "bob"},
        ),
        RuleTest(
            name="Github - Admin Added",
            expected_result=True,
            log={"actor": "cat", "action": "business.add_admin", "p_log_type": "GitHub.Audit", "user": "bob"},
        ),
        RuleTest(
            name="Github - Admin Invited",
            expected_result=True,
            log={"actor": "cat", "action": "business.invite_admin", "p_log_type": "GitHub.Audit", "user": "bob"},
        ),
        RuleTest(
            name="Github - Unknown Admin Role",
            expected_result=False,
            log={"actor": "cat", "action": "unknown.admin_role", "p_log_type": "GitHub.Audit", "user": "bob"},
        ),
        RuleTest(
            name="Zendesk - Admin Role Downgraded",
            expected_result=False,
            log={
                "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
                "id": 123456789123,
                "action_label": "Updated",
                "actor_id": 123,
                "source_id": 123,
                "source_type": "user",
                "source_label": "Bob Cat",
                "action": "update",
                "change_description": "Role changed from Administrator to End User",
                "ip_address": "127.0.0.1",
                "created_at": "2021-05-28T18:39:50Z",
                "p_log_type": "Zendesk.Audit",
            },
        ),
        RuleTest(
            name="Zendesk - Admin Role Assigned",
            expected_result=True,
            log={
                "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
                "id": 123456789123,
                "action_label": "Updated",
                "actor_id": 123,
                "source_id": 123,
                "source_type": "user",
                "source_label": "Bob Cat",
                "action": "update",
                "change_description": "Role changed from End User to Administrator",
                "ip_address": "127.0.0.1",
                "created_at": "2021-05-28T18:39:50Z",
                "p_log_type": "Zendesk.Audit",
            },
        ),
        RuleTest(
            name="Zendesk - App Admin Role Assigned",
            expected_result=True,
            log={
                "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
                "id": 123456789123,
                "action_label": "Updated",
                "actor_id": 123,
                "source_id": 123,
                "source_type": "user",
                "source_label": "Bob Cat",
                "action": "update",
                "change_description": "Explore role changed from not set to Admin\nGuide role changed from not set to Admin\nSupport role changed from not set to Admin\nTalk role changed from not set to Admin",
                "ip_address": "127.0.0.1",
                "created_at": "2021-05-28T18:39:50Z",
                "p_log_type": "Zendesk.Audit",
            },
        ),
        RuleTest(
            name="Asana - Normal Login",
            expected_result=False,
            log={
                "actor": {"actor_type": "user", "email": "homer@springfield.com", "gid": "2222222", "name": "Homer"},
                "context": {"client_ip_address": "8.8.8.8", "context_type": "web"},
                "created_at": "2021-10-21T23:38:10.364Z",
                "details": {"method": ["ONE_TIME_KEY"]},
                "event_category": "logins",
                "event_type": "user_login_succeeded",
                "gid": "222222222",
                "resource": {
                    "email": "homer@springfield.com",
                    "gid": "2222222",
                    "name": "homer",
                    "resource_type": "user",
                },
                "p_log_type": "Asana.Audit",
                "p_parse_time": "2021-06-04 10:02:33.650807",
                "p_event_time": "2021-06-04 09:59:53.650807",
            },
        ),
        RuleTest(
            name="Asana - Admin Added",
            expected_result=True,
            log={
                "actor": {"actor_type": "user", "name": "Homer"},
                "context": {"client_ip_address": "1.1.1.1", "context_type": "web"},
                "created_at": "2021-10-21T23:38:18.319Z",
                "details": {
                    "group": {
                        "gid": "11111",
                        "name": "1183399881404774.2lgxga.asanatest1.us",
                        "resource_type": "workspace",
                    },
                    "new_value": "member",
                    "old_value": "super_admin",
                },
                "event_category": "roles",
                "event_type": "user_workspace_admin_role_changed",
                "gid": "22222",
                "resource": {
                    "email": "marge@springfield.com",
                    "gid": "222222",
                    "name": "Marge Simpson",
                    "resource_type": "user",
                },
                "p_log_type": "Asana.Audit",
            },
        ),
    ]
