from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

standard_admin_role_assigned_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GCP - Admin Assigned",
        ExpectedResult=True,
        Log={
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
                            }
                        ]
                    },
                },
            },
            "p_log_type": "GCP.AuditLog",
        },
    ),
    PantherRuleTest(
        Name="GCP - Multiple Admin Roles Assigned",
        ExpectedResult=True,
        Log={
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
                        ]
                    },
                },
            },
            "p_log_type": "GCP.AuditLog",
        },
    ),
    PantherRuleTest(
        Name="GSuite - Other Admin Action",
        ExpectedResult=False,
        Log={
            "actor": {"email": "bobert@example.com"},
            "id": {"applicationName": "admin"},
            "events": [{"type": "DELEGATED_ADMIN_SETTINGS", "name": "RENAME_ROLE"}],
            "p_log_type": "GSuite.Reports",
        },
    ),
    PantherRuleTest(
        Name="GSuite - Privileges Assigned",
        ExpectedResult=True,
        Log={
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
                }
            ],
            "p_log_type": "GSuite.Reports",
        },
    ),
    PantherRuleTest(
        Name="OneLogin - Non permissions assigned event",
        ExpectedResult=False,
        Log={"event_type_id": 8, "p_log_type": "OneLogin.Events"},
    ),
    PantherRuleTest(
        Name="OneLogin - Non super user permissions assigned",
        ExpectedResult=False,
        Log={
            "event_type_id": 72,
            "privilege_name": "Manage users",
            "p_log_type": "OneLogin.Events",
        },
    ),
    PantherRuleTest(
        Name="OneLogin - Super user permissions assigned",
        ExpectedResult=True,
        Log={
            "event_type_id": 72,
            "privilege_name": "Super user",
            "user_name": "Evil Bob",
            "actor_user_name": "Bobert O'Bobly",
            "p_log_type": "OneLogin.Events",
        },
    ),
    PantherRuleTest(
        Name="Github - User Promoted",
        ExpectedResult=True,
        Log={
            "actor": "cat",
            "action": "team.promote_maintainer",
            "p_log_type": "GitHub.Audit",
            "user": "bob",
        },
    ),
    PantherRuleTest(
        Name="Github - Admin Added",
        ExpectedResult=True,
        Log={
            "actor": "cat",
            "action": "business.add_admin",
            "p_log_type": "GitHub.Audit",
            "user": "bob",
        },
    ),
    PantherRuleTest(
        Name="Github - Admin Invited",
        ExpectedResult=True,
        Log={
            "actor": "cat",
            "action": "business.invite_admin",
            "p_log_type": "GitHub.Audit",
            "user": "bob",
        },
    ),
    PantherRuleTest(
        Name="Github - Unknown Admin Role",
        ExpectedResult=False,
        Log={
            "actor": "cat",
            "action": "unknown.admin_role",
            "p_log_type": "GitHub.Audit",
            "user": "bob",
        },
    ),
    PantherRuleTest(
        Name="Zendesk - Admin Role Downgraded",
        ExpectedResult=False,
        Log={
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
    PantherRuleTest(
        Name="Zendesk - Admin Role Assigned",
        ExpectedResult=True,
        Log={
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
    PantherRuleTest(
        Name="Zendesk - App Admin Role Assigned",
        ExpectedResult=True,
        Log={
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
    PantherRuleTest(
        Name="Asana - Normal Login",
        ExpectedResult=False,
        Log={
            "actor": {
                "actor_type": "user",
                "email": "homer@springfield.com",
                "gid": "2222222",
                "name": "Homer",
            },
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
    PantherRuleTest(
        Name="Asana - Admin Added",
        ExpectedResult=True,
        Log={
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


class StandardAdminRoleAssigned(PantherRule):
    RuleID = "Standard.AdminRoleAssigned-prototype"
    DisplayName = "Admin Role Assigned"
    LogTypes = [
        LogType.Asana_Audit,
        LogType.Atlassian_Audit,
        LogType.GCP_AuditLog,
        LogType.GitHub_Audit,
        LogType.GSuite_Reports,
        LogType.OneLogin_Events,
        LogType.Zendesk_Audit,
    ]
    Tags = ["DataModel", "Privilege Escalation:Valid Accounts"]
    Severity = PantherSeverity.Medium
    Reports = {"MITRE ATT&CK": ["TA0004:T1078"]}
    Description = "Assigning an admin role manually could be a sign of privilege escalation"
    Runbook = "Verify with the user who attached the role or add to a allowlist"
    Reference = "https://medium.com/@gokulelango1040/privilege-escalation-attacks-28a9ef226abb"
    SummaryAttributes = ["p_any_ip_addresses"]
    Tests = standard_admin_role_assigned_tests

    def rule(self, event):
        # filter events on unified data model field
        return event.udm("event_type") == event_type.ADMIN_ROLE_ASSIGNED

    def title(self, event):
        # use unified data model field in title
        return f"{event.get('p_log_type')}: [{event.udm('actor_user')}] assigned admin privileges [{event.udm('assigned_admin_role')}] to [{event.udm('user')}]"

    def alert_context(self, event):
        return {
            "ips": event.get("p_any_ip_addresses", []),
            "actor": event.udm("actor_user"),
            "user": event.udm("user"),
        }
