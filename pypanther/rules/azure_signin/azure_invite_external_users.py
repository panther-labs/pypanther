from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.msft import azure_rule_context, azure_success


@panther_managed
class AzureAuditInviteExternalUsers(Rule):
    id = "Azure.Audit.InviteExternalUsers-prototype"
    display_name = "Azure Invite External Users"
    log_types = [LogType.AZURE_AUDIT]
    default_severity = Severity.LOW
    default_description = "This detection looks for a Azure users inviting external users\n"
    reports = {"MITRE ATT&CK": ["TA0001:T1078"]}
    default_runbook = "Verify the user permissions and investigate the external user details. If unauthorized, revoke access and block further invites. Update security policies.\n"
    default_reference = "https://learn.microsoft.com/en-us/entra/identity/authentication/overview-authentication"
    summary_attributes = [
        "properties:ServicePrincipalName",
        "properties:UserPrincipalName",
        "properties:initiatedBy:user:ipAddress",
    ]

    def rule(self, event):
        if not azure_success(event) or event.get("operationName") != "Invite external user":
            return False
        user_who_sent_invite = event.deep_get("properties", "initiatedBy", "user", "userPrincipalName", default="")
        user_who_received_invite = event.deep_walk(
            "properties",
            "additionalDetails",
            "value",
            return_val="last",
            default="",
        )
        domain = user_who_sent_invite.split("@")[-1]
        different_domain = not user_who_received_invite.endswith(domain)
        return different_domain

    def title(self, event):
        user_who_sent_invite = event.deep_get("properties", "initiatedBy", "user", "userPrincipalName", default="")
        user_who_received_invite = event.deep_walk(
            "properties",
            "additionalDetails",
            "value",
            return_val="last",
            default="",
        )
        return f"{user_who_sent_invite} invited {user_who_received_invite} to join as an EntraID member."

    def alert_context(self, event):
        return azure_rule_context(event)

    tests = [
        RuleTest(
            name="Successful Invite external user",
            expected_result=True,
            log={
                "callerIpAddress": "1.1.1.1",
                "category": "AuditLogs",
                "correlationId": "123456789",
                "durationMs": 0,
                "Level": 4,
                "operationName": "Invite external user",
                "operationVersion": "1.0",
                "properties": {
                    "activityDateTime": "2024-09-23 14:33:09.049661100",
                    "activityDisplayName": "Invite external user",
                    "additionalDetails": [
                        {"key": "oid", "value": "123456789"},
                        {"key": "tid", "value": "0123456789"},
                        {"key": "ipaddr", "value": "1.2.3.4"},
                        {"key": "wids", "value": "123456789"},
                        {"key": "InvitationId", "value": "123456789"},
                        {"key": "invitedUserEmailAddress", "value": "Kratos@climbingolympusrn.com"},
                    ],
                    "category": "UserManagement",
                    "correlationId": "123456789",
                    "id": "Invited Users_123456789",
                    "initiatedBy": {
                        "user": {
                            "id": "123456789",
                            "ipAddress": "1.2.3.4",
                            "roles": [],
                            "userPrincipalName": "Zeus@mtolympus.com",
                        },
                    },
                    "loggedByService": "Invited Users",
                    "operationType": "Add",
                    "result": "success",
                    "targetResources": [
                        {"administrativeUnits": [], "displayName": "Zeus.Theboss", "id": "123456789", "type": "User"},
                    ],
                },
                "resourceId": "/tenants/123456789/providers/Microsoft.aadiam",
                "resultSignature": "None",
                "tenantId": "123456789",
                "time": "2024-12-10 14:33:09.049661100",
            },
        ),
        RuleTest(
            name="Same org successful invite",
            expected_result=False,
            log={
                "callerIpAddress": "1.1.1.1",
                "category": "AuditLogs",
                "correlationId": "123456789",
                "durationMs": 0,
                "Level": 4,
                "operationName": "Invite external user",
                "operationVersion": "1.0",
                "properties": {
                    "activityDateTime": "2024-09-23 14:33:09.049661100",
                    "activityDisplayName": "Invite external user",
                    "additionalDetails": [
                        {"key": "oid", "value": "123456789"},
                        {"key": "tid", "value": "0123456789"},
                        {"key": "ipaddr", "value": "1.2.3.4"},
                        {"key": "wids", "value": "123456789"},
                        {"key": "InvitationId", "value": "123456789"},
                        {"key": "invitedUserEmailAddress", "value": "Kratos@mtolympus.com"},
                    ],
                    "category": "UserManagement",
                    "correlationId": "123456789",
                    "id": "Invited Users_123456789",
                    "initiatedBy": {
                        "user": {
                            "id": "123456789",
                            "ipAddress": "1.2.3.4",
                            "roles": [],
                            "userPrincipalName": "Zeus@mtolympus.com",
                        },
                    },
                    "loggedByService": "Invited Users",
                    "operationType": "Add",
                    "result": "success",
                    "targetResources": [
                        {"administrativeUnits": [], "displayName": "Zeus.Theboss", "id": "123456789", "type": "User"},
                    ],
                },
                "resourceId": "/tenants/123456789/providers/Microsoft.aadiam",
                "resultSignature": "None",
                "tenantId": "123456789",
                "time": "2024-12-10 14:33:09.049661100",
            },
        ),
        RuleTest(
            name="Unsuccessful invite",
            expected_result=False,
            log={
                "callerIpAddress": "1.1.1.1",
                "category": "AuditLogs",
                "correlationId": "123456789",
                "durationMs": 0,
                "Level": 4,
                "operationName": "Invite external user",
                "operationVersion": "1.0",
                "properties": {
                    "activityDateTime": "2024-09-23 14:33:09.049661100",
                    "activityDisplayName": "Invite external user",
                    "additionalDetails": [
                        {"key": "oid", "value": "123456789"},
                        {"key": "tid", "value": "0123456789"},
                        {"key": "ipaddr", "value": "1.2.3.4"},
                        {"key": "wids", "value": "123456789"},
                        {"key": "InvitationId", "value": "123456789"},
                        {"key": "invitedUserEmailAddress", "value": "Kratos@mtolympus.com"},
                    ],
                    "category": "UserManagement",
                    "correlationId": "123456789",
                    "id": "Invited Users_123456789",
                    "initiatedBy": {
                        "user": {
                            "id": "123456789",
                            "ipAddress": "1.2.3.4",
                            "roles": [],
                            "userPrincipalName": "Zeus@mtolympus.com",
                        },
                    },
                    "loggedByService": "Invited Users",
                    "operationType": "Add",
                    "result": "failed",
                    "targetResources": [
                        {"administrativeUnits": [], "displayName": "Zeus.Theboss", "id": "123456789", "type": "User"},
                    ],
                },
                "resourceId": "/tenants/123456789/providers/Microsoft.aadiam",
                "resultSignature": "None",
                "tenantId": "123456789",
                "time": "2024-12-10 14:33:09.049661100",
            },
        ),
        RuleTest(
            name="Not external invite",
            expected_result=False,
            log={
                "callerIpAddress": "1.1.1.1",
                "category": "AuditLogs",
                "correlationId": "123456789",
                "durationMs": 0,
                "Level": 4,
                "operationName": "Invite Internal User",
                "operationVersion": "1.0",
                "properties": {
                    "activityDateTime": "2024-09-23 14:33:09.049661100",
                    "activityDisplayName": "Invite external user",
                    "additionalDetails": [
                        {"key": "oid", "value": "123456789"},
                        {"key": "tid", "value": "0123456789"},
                        {"key": "ipaddr", "value": "1.2.3.4"},
                        {"key": "wids", "value": "123456789"},
                        {"key": "InvitationId", "value": "123456789"},
                        {"key": "invitedUserEmailAddress", "value": "Kratos@mtolympus.com"},
                    ],
                    "category": "UserManagement",
                    "correlationId": "123456789",
                    "id": "Invited Users_123456789",
                    "initiatedBy": {
                        "user": {
                            "id": "123456789",
                            "ipAddress": "1.2.3.4",
                            "roles": [],
                            "userPrincipalName": "Zeus@mtolympus.com",
                        },
                    },
                    "loggedByService": "Invited Users",
                    "operationType": "Add",
                    "result": "success",
                    "targetResources": [
                        {"administrativeUnits": [], "displayName": "Zeus.Theboss", "id": "123456789", "type": "User"},
                    ],
                },
                "resourceId": "/tenants/123456789/providers/Microsoft.aadiam",
                "resultSignature": "None",
                "tenantId": "123456789",
                "time": "2024-12-10 14:33:09.049661100",
            },
        ),
    ]
