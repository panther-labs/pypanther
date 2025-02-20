from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.msft import azure_rule_context, azure_success, get_target_name


@panther_managed
class AzureAuditRoleChangedPIM(Rule):
    id = "Azure.Audit.RoleChangedPIM-prototype"
    display_name = "Azure Role Changed PIM"
    log_types = [LogType.AZURE_AUDIT]
    default_severity = Severity.MEDIUM
    dedup_period_minutes = 0
    default_description = "This detection looks for a change in member's PIM roles in EntraID\n"
    reports = {"MITRE ATT&CK": ["TA0042:T1586"]}
    default_runbook = "Verify if the role change was authorized and review the affected user. If unauthorized, revert the role change, notify relevant teams,\n"
    default_reference = "https://learn.microsoft.com/en-us/entra/identity/authentication/overview-authentication"
    summary_attributes = ["properties:ServicePrincipalName", "properties:UserPrincipalName", "properties:ipAddress"]

    def rule(self, event):
        operation = event.get("operationName", default="")
        if azure_success(event) and "Add member to role in PIM completed" in operation:
            return True
        return False

    def title(self, event):
        operation_name = event.get("operationName", default="<UNKNOWN OPERATION>")
        actor_name = event.deep_get("properties", "initiatedBy", "user", "userPrincipalName", default="<UNKNOWN USER>")
        target_name = get_target_name(event)
        role = event.deep_walk(
            "properties",
            "targetResources",
            "displayName",
            return_val="first",
            default="<UNKNOWN_ROLE>",
        )
        return f"{actor_name} added {target_name} as {role} successfully with {operation_name}"

    def alert_context(self, event):
        return azure_rule_context(event)

    tests = [
        RuleTest(
            name="Successfully added PIM role",
            expected_result=True,
            log={
                "category": "AuditLogs",
                "correlationId": "1234155",
                "durationMs": 0,
                "identity": "Ju Cho",
                "Level": 4,
                "operationName": "Add member to role in PIM completed (permanent)",
                "operationVersion": "1.0",
                "properties": {
                    "activityDateTime": "2024-12-16 16:32:16.087554000",
                    "activityDisplayName": "Add member to role in PIM completed (permanent)",
                    "additionalDetails": [
                        {"key": "RoleDefinitionOriginId", "value": "123451235"},
                        {"key": "RoleDefinitionOriginType", "value": "BuiltInRole"},
                        {"key": "TemplateId", "value": "123412351"},
                        {"key": "StartTime", "value": "2024-12-16T16:32:15.8441686Z"},
                        {"key": "Justification", "value": "test assign"},
                        {"key": "oid", "value": "12351534"},
                        {"key": "tid", "value": "345667733"},
                        {"key": "wids", "value": "234523454"},
                        {"key": "ipaddr", "value": "1.2.3.4"},
                        {"key": "RequestId", "value": "651346123452"},
                    ],
                    "category": "RoleManagement",
                    "correlationId": "12345",
                    "id": "PIM_123415",
                    "initiatedBy": {
                        "user": {
                            "displayName": "Ju Cho",
                            "id": "12345",
                            "roles": [],
                            "userPrincipalName": "Radahn@Starscourge.onmicrosoft.com",
                        },
                    },
                    "loggedByService": "PIM",
                    "operationType": "Update",
                    "result": "success",
                    "resultReason": "test assign",
                    "targetResources": [
                        {
                            "administrativeUnits": [],
                            "displayName": "Application Administrator",
                            "id": "12345",
                            "modifiedProperties": [
                                {"displayName": "RoleDefinitionOriginId", "newValue": '"12345"', "oldValue": '""'},
                                {
                                    "displayName": "RoleDefinitionOriginType",
                                    "newValue": '"BuiltInRole"',
                                    "oldValue": '""',
                                },
                                {"displayName": "TemplateId", "newValue": '"12345"', "oldValue": '""'},
                            ],
                            "type": "Role",
                        },
                        {"administrativeUnits": [], "id": "12345", "type": "Request"},
                        {"administrativeUnits": [], "displayName": "Malenia", "id": "12345", "type": "User"},
                        {"administrativeUnits": [], "displayName": "Panther", "id": "12345", "type": "Directory"},
                        {"administrativeUnits": [], "id": "12345", "type": "Other"},
                    ],
                },
                "resourceId": "/tenants/12345/providers/Microsoft.aadiam",
                "resultSignature": "None",
                "tenantId": "12345",
                "time": "2024-12-16 16:32:16.087554000",
            },
        ),
        RuleTest(
            name="requested adding PIM role",
            expected_result=False,
            log={
                "category": "AuditLogs",
                "correlationId": "1234155",
                "durationMs": 0,
                "identity": "Ju Cho",
                "Level": 4,
                "operationName": "Add member to role in PIM requested (permanent)",
                "operationVersion": "1.0",
                "properties": {
                    "activityDateTime": "2024-12-16 16:32:16.087554000",
                    "activityDisplayName": "Add member to role in PIM requested (permanent)",
                    "additionalDetails": [
                        {"key": "RoleDefinitionOriginId", "value": "123451235"},
                        {"key": "RoleDefinitionOriginType", "value": "BuiltInRole"},
                        {"key": "TemplateId", "value": "123412351"},
                        {"key": "StartTime", "value": "2024-12-16T16:32:15.8441686Z"},
                        {"key": "Justification", "value": "test assign"},
                        {"key": "oid", "value": "12351534"},
                        {"key": "tid", "value": "345667733"},
                        {"key": "wids", "value": "234523454"},
                        {"key": "ipaddr", "value": "1.2.3.4"},
                        {"key": "RequestId", "value": "651346123452"},
                    ],
                    "category": "RoleManagement",
                    "correlationId": "12345",
                    "id": "PIM_123415",
                    "initiatedBy": {
                        "user": {
                            "displayName": "Ju Cho",
                            "id": "12345",
                            "roles": [],
                            "userPrincipalName": "Radahn@Starscourge.onmicrosoft.com",
                        },
                    },
                    "loggedByService": "PIM",
                    "operationType": "Update",
                    "result": "success",
                    "resultReason": "test assign",
                    "targetResources": [
                        {
                            "administrativeUnits": [],
                            "displayName": "Application Administrator",
                            "id": "12345",
                            "modifiedProperties": [
                                {"displayName": "RoleDefinitionOriginId", "newValue": '"12345"', "oldValue": '""'},
                                {
                                    "displayName": "RoleDefinitionOriginType",
                                    "newValue": '"BuiltInRole"',
                                    "oldValue": '""',
                                },
                                {"displayName": "TemplateId", "newValue": '"12345"', "oldValue": '""'},
                            ],
                            "type": "Role",
                        },
                        {"administrativeUnits": [], "id": "12345", "type": "Request"},
                        {"administrativeUnits": [], "displayName": "Malenia", "id": "12345", "type": "User"},
                        {"administrativeUnits": [], "displayName": "Panther", "id": "12345", "type": "Directory"},
                        {"administrativeUnits": [], "id": "12345", "type": "Other"},
                    ],
                },
                "resourceId": "/tenants/12345/providers/Microsoft.aadiam",
                "resultSignature": "None",
                "tenantId": "12345",
                "time": "2024-12-16 16:32:16.087554000",
            },
        ),
        RuleTest(
            name="Add member to role (Non PIM)",
            expected_result=False,
            log={
                "category": "AuditLogs",
                "correlationId": "1234155",
                "durationMs": 0,
                "identity": "Ju Cho",
                "Level": 4,
                "operationName": "Add member to role",
                "operationVersion": "1.0",
                "properties": {
                    "activityDateTime": "2024-12-16 16:32:16.087554000",
                    "activityDisplayName": "Add member to role",
                    "additionalDetails": [
                        {"key": "RoleDefinitionOriginId", "value": "123451235"},
                        {"key": "RoleDefinitionOriginType", "value": "BuiltInRole"},
                        {"key": "TemplateId", "value": "123412351"},
                        {"key": "StartTime", "value": "2024-12-16T16:32:15.8441686Z"},
                        {"key": "Justification", "value": "test assign"},
                        {"key": "oid", "value": "12351534"},
                        {"key": "tid", "value": "345667733"},
                        {"key": "wids", "value": "234523454"},
                        {"key": "ipaddr", "value": "1.2.3.4"},
                        {"key": "RequestId", "value": "651346123452"},
                    ],
                    "category": "RoleManagement",
                    "correlationId": "12345",
                    "id": "PIM_123415",
                    "initiatedBy": {
                        "user": {
                            "displayName": "Ju Cho",
                            "id": "12345",
                            "roles": [],
                            "userPrincipalName": "Radahn@Starscourge.onmicrosoft.com",
                        },
                    },
                    "loggedByService": "PIM",
                    "operationType": "Update",
                    "result": "success",
                    "resultReason": "test assign",
                    "targetResources": [
                        {
                            "administrativeUnits": [],
                            "displayName": "Application Administrator",
                            "id": "12345",
                            "modifiedProperties": [
                                {"displayName": "RoleDefinitionOriginId", "newValue": '"12345"', "oldValue": '""'},
                                {
                                    "displayName": "RoleDefinitionOriginType",
                                    "newValue": '"BuiltInRole"',
                                    "oldValue": '""',
                                },
                                {"displayName": "TemplateId", "newValue": '"123415"', "oldValue": '""'},
                            ],
                            "type": "Role",
                        },
                        {"administrativeUnits": [], "id": "12345", "type": "Request"},
                        {"administrativeUnits": [], "displayName": "Malenia", "id": "12345", "type": "User"},
                        {"administrativeUnits": [], "displayName": "Panther", "id": "12345", "type": "Directory"},
                        {"administrativeUnits": [], "id": "12345", "type": "Other"},
                    ],
                },
                "resourceId": "/tenants/12345/providers/Microsoft.aadiam",
                "resultSignature": "None",
                "tenantId": "12345",
                "time": "2024-12-16 16:32:16.087554000",
            },
        ),
    ]
