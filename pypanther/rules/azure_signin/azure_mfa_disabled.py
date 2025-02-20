import json

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.base import deep_walk
from pypanther.helpers.msft import azure_rule_context


@panther_managed
class AzureAuditMFADisabled(Rule):
    id = "Azure.Audit.MFADisabled-prototype"
    display_name = "Azure MFA Disabled"
    log_types = [LogType.AZURE_AUDIT]
    default_severity = Severity.HIGH
    default_description = "This detection looks for MFA being disabled in conditional access policy\n"
    reports = {"MITRE ATT&CK": ["TA0005:T1556", "TA0001:T1078"]}
    default_runbook = "Verify if the change was authorized and investigate the user activity. If unauthorized, re-enable MFA, revoke access.\n"
    default_reference = "https://learn.microsoft.com/en-us/entra/identity/authentication/overview-authentication"
    summary_attributes = ["properties:ServicePrincipalName", "properties:UserPrincipalName", "properties:ipAddress"]

    def get_mfa(self, policy):
        parse_one = json.loads(policy)
        mfa_get = deep_walk(parse_one, "grantControls", "builtInControls", default=[])
        mfa_standardized = [n.lower() for n in mfa_get]
        return mfa_standardized

    def rule(self, event):
        if event.get("operationName", default="") != "Update conditional access policy":
            return False
        old_value = event.deep_walk(
            "properties",
            "targetResources",
            "modifiedProperties",
            "oldValue",
            return_val="first",
            default="",
        )
        new_value = event.deep_walk(
            "properties",
            "targetResources",
            "modifiedProperties",
            "newValue",
            return_val="first",
            default="",
        )
        old_value_parsed = self.get_mfa(old_value)
        new_value_parsed = self.get_mfa(new_value)
        return "mfa" in old_value_parsed and "mfa" not in new_value_parsed

    def title(self, event):
        actor_name = event.deep_get("properties", "initiatedBy", "user", "userPrincipalName", default="<UNKNOWN ACTOR>")
        policy = event.deep_walk("properties", "targetResources", "displayName", default="")
        return f"MFA disabled by {actor_name} on the policy {policy}"

    def alert_context(self, event):
        return azure_rule_context(event)

    tests = [
        RuleTest(
            name="MFA Disabled Successful",
            expected_result=True,
            log={
                "time": "2024-11-27T03:31:26.7088498Z",
                "resourceId": "/tenants/123456789/providers/Microsoft.aadiam",
                "operationName": "Update conditional access policy",
                "operationVersion": "1.0",
                "category": "AuditLogs",
                "tenantId": "123456789",
                "resultSignature": "None",
                "durationMs": 0,
                "callerIpAddress": "1.2.3.4",
                "correlationId": "123456789",
                "Level": 4,
                "properties": {
                    "tenantId": "123456789",
                    "resultType": "",
                    "resultDescription": "",
                    "operationName": "Update conditional access policy",
                    "identity": "",
                    "tenantGeo": "NA",
                    "id": "IPCGraph_123456789",
                    "category": "Policy",
                    "correlationId": "123456789",
                    "result": "success",
                    "resultReason": None,
                    "activityDisplayName": "Update conditional access policy",
                    "activityDateTime": "2024-11-27T03:31:26.7088498+00:00",
                    "loggedByService": "Conditional Access",
                    "operationType": "Update",
                    "userAgent": None,
                    "initiatedBy": {
                        "user": {
                            "id": "123456789b",
                            "displayName": None,
                            "userPrincipalName": "Kratos@onmicrosoft.com",
                            "ipAddress": "1.2.3.4",
                            "roles": [],
                        },
                    },
                    "targetResources": [
                        {
                            "id": "123456789",
                            "displayName": "MFA",
                            "type": "Policy",
                            "modifiedProperties": [
                                {
                                    "displayName": "ConditionalAccessPolicy",
                                    "oldValue": '{"id":"123456789","displayName":"MFA","createdDateTime":"2024-11-21T16:48:48.1196443+00:00","modifiedDateTime":"2024-11-21T16:56:13.9120766+00:00","state":"enabled","conditions":{"applications":{"includeApplications":["None"],"excludeApplications":[],"includeUserActions":[],"includeAuthenticationContextClassReferences":[],"applicationFilter":null},"users":{"includeUsers":["All"],"excludeUsers":[],"includeGroups":[],"excludeGroups":[],"includeRoles":[],"excludeRoles":[]},"userRiskLevels":[],"signInRiskLevels":[],"clientAppTypes":["all"],"servicePrincipalRiskLevels":[]},"grantControls":{"operator":"OR","builtInControls":["MFA"],"customAuthenticationFactors":[],"termsOfUse":[]},"sessionControls":{"signInFrequency":{"value":90,"type":"days","authenticationType":"primaryAndSecondaryAuthentication","frequencyInterval":"timeBased","isEnabled":true}}}',
                                    "newValue": '{"id":"123456789","displayName":"MFA","createdDateTime":"2024-11-21T16:48:48.1196443+00:00","modifiedDateTime":"2024-11-27T03:31:25.4989035+00:00","state":"enabled","conditions":{"applications":{"includeApplications":["None"],"excludeApplications":[],"includeUserActions":[],"includeAuthenticationContextClassReferences":[],"applicationFilter":null},"users":{"includeUsers":["All"],"excludeUsers":[],"includeGroups":[],"excludeGroups":[],"includeRoles":[],"excludeRoles":[]},"userRiskLevels":[],"signInRiskLevels":[],"clientAppTypes":["all"],"servicePrincipalRiskLevels":[]},"sessionControls":{"signInFrequency":{"value":90,"type":"days","authenticationType":"primaryAndSecondaryAuthentication","frequencyInterval":"timeBased","isEnabled":true}}}',
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
            name="MFA Enabled",
            expected_result=False,
            log={
                "time": "2024-11-27T03:31:26.7088498Z",
                "resourceId": "/tenants/123456789/providers/Microsoft.aadiam",
                "operationName": "Update conditional access policy",
                "operationVersion": "1.0",
                "category": "AuditLogs",
                "tenantId": "123456789",
                "resultSignature": "None",
                "durationMs": 0,
                "callerIpAddress": "1.2.3.4",
                "correlationId": "123456789",
                "Level": 4,
                "properties": {
                    "tenantId": "123456789",
                    "resultType": "",
                    "resultDescription": "",
                    "operationName": "Update conditional access policy",
                    "identity": "",
                    "tenantGeo": "NA",
                    "id": "IPCGraph_123456789",
                    "category": "Policy",
                    "correlationId": "123456789",
                    "result": "success",
                    "resultReason": None,
                    "activityDisplayName": "Update conditional access policy",
                    "activityDateTime": "2024-11-27T03:31:26.7088498+00:00",
                    "loggedByService": "Conditional Access",
                    "operationType": "Update",
                    "userAgent": None,
                    "initiatedBy": {
                        "user": {
                            "id": "123456789b",
                            "displayName": None,
                            "userPrincipalName": "Kratos@onmicrosoft.com",
                            "ipAddress": "1.2.3.4",
                            "roles": [],
                        },
                    },
                    "targetResources": [
                        {
                            "id": "123456789",
                            "displayName": "MFA",
                            "type": "Policy",
                            "modifiedProperties": [
                                {
                                    "displayName": "ConditionalAccessPolicy",
                                    "oldValue": '{"id":"123456789","displayName":"MFA","createdDateTime":"2024-11-21T16:48:48.1196443+00:00","modifiedDateTime":"2024-11-27T03:31:25.4989035+00:00","state":"enabled","conditions":{"applications":{"includeApplications":["None"],"excludeApplications":[],"includeUserActions":[],"includeAuthenticationContextClassReferences":[],"applicationFilter":null},"users":{"includeUsers":["All"],"excludeUsers":[],"includeGroups":[],"excludeGroups":[],"includeRoles":[],"excludeRoles":[]},"userRiskLevels":[],"signInRiskLevels":[],"clientAppTypes":["all"],"servicePrincipalRiskLevels":[]},"sessionControls":{"signInFrequency":{"value":90,"type":"days","authenticationType":"primaryAndSecondaryAuthentication","frequencyInterval":"timeBased","isEnabled":true}}}',
                                    "newValue": '{"id":"123456789","displayName":"MFA","createdDateTime":"2024-11-21T16:48:48.1196443+00:00","modifiedDateTime":"2024-11-21T16:56:13.9120766+00:00","state":"enabled","conditions":{"applications":{"includeApplications":["None"],"excludeApplications":[],"includeUserActions":[],"includeAuthenticationContextClassReferences":[],"applicationFilter":null},"users":{"includeUsers":["All"],"excludeUsers":[],"includeGroups":[],"excludeGroups":[],"includeRoles":[],"excludeRoles":[]},"userRiskLevels":[],"signInRiskLevels":[],"clientAppTypes":["all"],"servicePrincipalRiskLevels":[]},"grantControls":{"operator":"OR","builtInControls":["MFA"],"customAuthenticationFactors":[],"termsOfUse":[]},"sessionControls":{"signInFrequency":{"value":90,"type":"days","authenticationType":"primaryAndSecondaryAuthentication","frequencyInterval":"timeBased","isEnabled":true}}}',
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
            name="MFA Disabled from another log",
            expected_result=False,
            log={
                "time": "2024-11-27T03:31:26.2934305Z",
                "resourceId": "/tenants/123456/providers/Microsoft.aadiam",
                "operationName": "Update policy",
                "operationVersion": "1.0",
                "category": "AuditLogs",
                "tenantId": "123456",
                "resultSignature": "None",
                "durationMs": 0,
                "callerIpAddress": "1.2.3.4",
                "correlationId": "123456",
                "Level": 4,
                "properties": {
                    "tenantId": "123456",
                    "resultType": "",
                    "resultDescription": "",
                    "operationName": "Update policy",
                    "identity": "",
                    "tenantGeo": "NA",
                    "id": "Directory_123145",
                    "category": "Policy",
                    "correlationId": "1235134516",
                    "result": "success",
                    "resultReason": "",
                    "activityDisplayName": "Update policy",
                    "activityDateTime": "2024-11-27T03:31:26.2934305+00:00",
                    "loggedByService": "Core Directory",
                    "operationType": "Update",
                    "userAgent": None,
                    "initiatedBy": {
                        "user": {
                            "id": "1324512355",
                            "displayName": None,
                            "userPrincipalName": "Kratos@onmicrosoft.com",
                            "ipAddress": "1.2.3.4",
                            "roles": [],
                        },
                    },
                    "targetResources": [
                        {
                            "id": "12351254",
                            "displayName": "MFA",
                            "type": "Policy",
                            "modifiedProperties": [
                                {
                                    "displayName": "PolicyDetail",
                                    "oldValue": '["{\\"Version\\":1,\\"CreatedDateTime\\":\\"2024-11-21T16:48:48.1196443Z\\",\\"ModifiedDateTime\\":\\"2024-11-21T16:56:13.9120766Z\\",\\"State\\":\\"Enabled\\",\\"Conditions\\":{\\"Applications\\":{\\"Include\\":[{\\"Applications\\":[\\"None\\"]}]},\\"Users\\":{\\"Include\\":[{\\"Users\\":[\\"All\\"]}]}},\\"Controls\\":[{\\"Control\\":[\\"Mfa\\"]}],\\"SessionControls\\":[\\"SignInFrequency\\"],\\"SignInFrequencyTimeSpan\\":\\"90.00:00:00\\",\\"SignInFrequencyType\\":10,\\"EnforceAllPoliciesForEas\\":true,\\"IncludeOtherLegacyClientTypeForEvaluation\\":true}"]',
                                    "newValue": '["{\\"Version\\":1,\\"CreatedDateTime\\":\\"2024-11-21T16:48:48.1196443Z\\",\\"ModifiedDateTime\\":\\"2024-11-27T03:31:25.4989035Z\\",\\"State\\":\\"Enabled\\",\\"Conditions\\":{\\"Applications\\":{\\"Include\\":[{\\"Applications\\":[\\"None\\"]}]},\\"Users\\":{\\"Include\\":[{\\"Users\\":[\\"All\\"]}]}},\\"SessionControls\\":[\\"SignInFrequency\\"],\\"SignInFrequencyTimeSpan\\":\\"90.00:00:00\\",\\"SignInFrequencyType\\":10,\\"EnforceAllPoliciesForEas\\":true,\\"IncludeOtherLegacyClientTypeForEvaluation\\":true}"]',
                                },
                                {
                                    "displayName": "Included Updated Properties",
                                    "oldValue": None,
                                    "newValue": '"PolicyDetail"',
                                },
                            ],
                            "administrativeUnits": [],
                        },
                    ],
                    "additionalDetails": [{"key": "User-Agent", "value": "Microsoft Azure Graph Client Library 1.0"}],
                },
            },
        ),
    ]
