from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.msft import azure_rule_context, azure_success


@panther_managed
class AzureAuditPolicyChanged(Rule):
    id = "Azure.Audit.PolicyChanged-prototype"
    display_name = "Azure Policy Changed"
    log_types = [LogType.AZURE_AUDIT]
    default_severity = Severity.LOW
    dedup_period_minutes = 10
    default_description = "This detection looks for policy changes in AuditLogs\n"
    reports = {"MITRE ATT&CK": ["TA0005:T1526"]}
    default_runbook = "Verify if the change was authorized and review the modifications. If unauthorized, revert the policy, notify relevant teams, and investigate the user actions.\n"
    default_reference = "https://learn.microsoft.com/en-us/entra/identity/authentication/overview-authentication"
    summary_attributes = [
        "properties:ServicePrincipalName",
        "properties:UserPrincipalName",
        "properties:initiatedBy:user:ipAddress",
    ]
    POLICY_OPERATION = "policy"
    IGNORE_ACTIONS = ["Add", "Added"]

    def rule(self, event):
        operation = event.get("operationName", default="")
        if not azure_success(event) or not operation.endswith(self.POLICY_OPERATION):
            return False
        # Ignore added policies
        if any(operation.startswith(ignore) for ignore in self.IGNORE_ACTIONS):
            return False
        return True

    def title(self, event):
        operation_name = event.get("operationName", default="<UNKNOWN OPERATION>")
        actor_name = event.deep_get("properties", "initiatedBy", "user", "userPrincipalName", default="<UNKNOWN ACTOR>")
        policy = event.deep_walk("properties", "targetResources", "displayName", default="<UNKNOWN POLICY>")
        return f"{operation_name} by {actor_name} on the policy {policy}"

    def alert_context(self, event):
        return azure_rule_context(event)

    tests = [
        RuleTest(
            name="Policy Changed",
            expected_result=True,
            log={
                "time": "2024-12-10T02:22:58.7270280Z",
                "resourceId": "/tenants/123145/providers/Microsoft.aadiam",
                "operationName": "Delete conditional access policy",
                "operationVersion": "1.0",
                "category": "AuditLogs",
                "tenantId": "12341234",
                "resultSignature": "None",
                "durationMs": 0,
                "callerIpAddress": "1.2.3.4",
                "correlationId": "1324515",
                "Level": 4,
                "properties": {
                    "tenantId": "132455112",
                    "resultType": "",
                    "resultDescription": "",
                    "operationName": "Delete conditional access policy",
                    "identity": "",
                    "tenantGeo": "NA",
                    "id": "IPCGraph_af23466234",
                    "category": "Policy",
                    "correlationId": "23456234",
                    "result": "success",
                    "resultReason": None,
                    "activityDisplayName": "Delete conditional access policy",
                    "activityDateTime": "2024-11-27T02:22:58.727028+00:00",
                    "loggedByService": "Conditional Access",
                    "operationType": "Delete",
                    "userAgent": None,
                    "initiatedBy": {
                        "user": {
                            "id": "234526234",
                            "displayName": None,
                            "userPrincipalName": "Kratos@mtolympus.com",
                            "ipAddress": "1.2.3.4",
                            "roles": [],
                        },
                    },
                    "targetResources": [
                        {
                            "id": "5e3cb481-2814-4295-b4cc-2440a6d66c86",
                            "displayName": "Outside MFA",
                            "type": "Policy",
                            "modifiedProperties": [
                                {
                                    "displayName": "ConditionalAccessPolicy",
                                    "oldValue": '{"id":"5e3cb481-2814-4295-b4cc-2440a6d66c86","displayName":"Outside MFA","createdDateTime":"2024-11-27T02:22:19.8926587+00:00","state":"enabled","conditions":{"applications":{"includeApplications":["None"],"excludeApplications":[],"includeUserActions":[],"includeAuthenticationContextClassReferences":[],"applicationFilter":null},"users":{"includeUsers":[],"excludeUsers":[],"includeGroups":[],"excludeGroups":[],"includeRoles":[],"excludeRoles":[],"includeGuestsOrExternalUsers":{"guestOrExternalUserTypes":63,"externalTenants":{}}},"userRiskLevels":[],"signInRiskLevels":[],"clientAppTypes":["all"],"servicePrincipalRiskLevels":[]},"grantControls":{"operator":"OR","builtInControls":["mfa"],"customAuthenticationFactors":[],"termsOfUse":[]}}',
                                    "newValue": None,
                                },
                            ],
                            "administrativeUnits": [],
                        },
                    ],
                    "additionalDetails": [{"key": "Category", "value": "Conditional Access"}],
                },
            },
        ),
        RuleTest(
            name="Policy Updated",
            expected_result=True,
            log={
                "time": "2024-11-21T16:47:21.6424070Z",
                "resourceId": "/tenants/1234155/providers/Microsoft.aadiam",
                "operationName": "Update policy",
                "operationVersion": "1.0",
                "category": "AuditLogs",
                "tenantId": "12341235",
                "resultSignature": "None",
                "durationMs": 0,
                "callerIpAddress": "1.2.3.4",
                "correlationId": "124412123",
                "Level": 4,
                "properties": {
                    "tenantId": "123515-5-1235",
                    "resultType": "",
                    "resultDescription": "",
                    "operationName": "Update policy",
                    "identity": "",
                    "tenantGeo": "NA",
                    "id": "Directory_12351123",
                    "category": "Policy",
                    "correlationId": "12341513",
                    "result": "success",
                    "resultReason": "",
                    "activityDisplayName": "Delete policy",
                    "activityDateTime": "2024-11-21T16:47:21.642407+00:00",
                    "loggedByService": "Core Directory",
                    "operationType": "Delete",
                    "userAgent": None,
                    "initiatedBy": {
                        "user": {
                            "id": "12345123",
                            "displayName": None,
                            "userPrincipalName": "Kratos@onmicrosoft.com",
                            "ipAddress": "1.2.3.4",
                            "roles": [],
                        },
                    },
                    "targetResources": [
                        {
                            "id": "123451516",
                            "displayName": "Require multifactor authentication for all users",
                            "type": "Policy",
                            "modifiedProperties": [],
                            "administrativeUnits": [],
                        },
                    ],
                    "additionalDetails": [{"key": "User-Agent", "value": "Microsoft Azure Graph Client Library 1.0"}],
                },
            },
        ),
        RuleTest(
            name="Policy Added",
            expected_result=False,
            log={
                "time": "2024-11-21T16:47:21.6424070Z",
                "resourceId": "/tenants/1234155/providers/Microsoft.aadiam",
                "operationName": "Added policy",
                "operationVersion": "1.0",
                "category": "AuditLogs",
                "tenantId": "12341235",
                "resultSignature": "None",
                "durationMs": 0,
                "ipAddress": "1.2.3.4",
                "correlationId": "124412123",
                "Level": 4,
                "properties": {
                    "tenantId": "123515-5-1235",
                    "resultType": "",
                    "resultDescription": "",
                    "operationName": "Added policy",
                    "identity": "",
                    "tenantGeo": "NA",
                    "id": "Directory_12351123",
                    "category": "Policy",
                    "correlationId": "12341513",
                    "result": "success",
                    "resultReason": "",
                    "activityDisplayName": "Added policy",
                    "activityDateTime": "2024-11-21T16:47:21.642407+00:00",
                    "loggedByService": "Core Directory",
                    "operationType": "Delete",
                    "userAgent": None,
                    "initiatedBy": {
                        "user": {
                            "id": "12345123",
                            "displayName": None,
                            "userPrincipalName": "Kratos@onmicrosoft.com",
                            "ipAddress": "1.2.3.4",
                            "roles": [],
                        },
                    },
                    "targetResources": [
                        {
                            "id": "123451516",
                            "displayName": "Require multifactor authentication for all users",
                            "type": "Policy",
                            "modifiedProperties": [],
                            "administrativeUnits": [],
                        },
                    ],
                    "additionalDetails": [{"key": "User-Agent", "value": "Microsoft Azure Graph Client Library 1.0"}],
                },
            },
        ),
    ]
