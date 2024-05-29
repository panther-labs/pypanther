from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_azuresignin_helpers import (
    actor_user,
    azure_signin_alert_context,
    is_sign_in_event,
)
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

azure_audit_risk_level_passthrough_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Failed Sign-In",
        ExpectedResult=False,
        Log={
            "calleripaddress": "12.12.12.12",
            "category": "ServicePrincipalSignInLogs",
            "correlationid": "e1f237ef-6548-4172-be79-03818c04c06e",
            "durationms": 0,
            "level": 4,
            "location": "IE",
            "operationname": "Sign-in activity",
            "operationversion": 1,
            "p_event_time": "2023-07-26 23:00:20.889",
            "p_log_type": "Azure.Audit",
            "properties": {
                "appId": "cfceb902-8fab-4f8c-88ba-374d3c975c3a",
                "authenticationProcessingDetails": [
                    {"key": "Azure AD App Authentication Library", "value": ""}
                ],
                "authenticationProtocol": "none",
                "clientCredentialType": "none",
                "conditionalAccessStatus": "notApplied",
                "correlationId": "5889315c-c4ac-4807-99da-e17417eae786",
                "createdDateTime": "2023-07-26 22:58:30.983201900",
                "crossTenantAccessType": "none",
                "flaggedForReview": False,
                "id": "36658c78-02d9-4d8f-84ee-5ca4a3fdefef",
                "incomingTokenType": "none",
                "ipAddress": "12.12.12.12",
                "isInteractive": False,
                "isTenantRestricted": False,
                "location": {
                    "city": "Dublin",
                    "countryOrRegion": "IE",
                    "geoCoordinates": {
                        "latitude": 51.35555555555555,
                        "longitude": -5.244444444444444,
                    },
                    "state": "Dublin",
                },
                "managedIdentityType": "none",
                "processingTimeInMilliseconds": 0,
                "resourceDisplayName": "Azure Storage",
                "resourceId": "037694de-8c7d-498d-917d-edb650090fa5",
                "resourceServicePrincipalId": "a225221f-8cc5-411a-9cc7-5e1394b8a5b8",
                "riskDetail": "none",
                "riskLevelAggregated": "none",
                "riskLevelDuringSignIn": "none",
                "riskState": "none",
                "servicePrincipalId": "b1c34143-e405-4058-8e29-84596ad737b8",
                "servicePrincipalName": "some-service-principal",
                "status": {"errorCode": 7000215},
                "tokenIssuerType": "AzureAD",
                "uniqueTokenIdentifier": "NDDDDDDDDDDDDDDDDDD_DD",
            },
            "resourceid": "/tenants/c0dd2fa0-71be-4df8-b2a6-24cee7de069a/providers/Microsoft.aadiam",
            "resultsignature": "None",
            "resulttype": 7000215,
            "tenantid": "a2aa49aa-2c0c-49d2-af87-f402c421df0b",
            "time": "2023-07-26 23:00:20.889",
        },
    ),
    PantherRuleTest(
        Name="Failed Sign-In with riskLevelAggregated",
        ExpectedResult=True,
        Log={
            "calleripaddress": "12.12.12.12",
            "category": "ServicePrincipalSignInLogs",
            "correlationid": "e1f237ef-6548-4172-be79-03818c04c06e",
            "durationms": 0,
            "level": 4,
            "location": "IE",
            "operationname": "Sign-in activity",
            "operationversion": 1,
            "p_event_time": "2023-07-26 23:00:20.889",
            "p_log_type": "Azure.Audit",
            "properties": {
                "appId": "cfceb902-8fab-4f8c-88ba-374d3c975c3a",
                "authenticationProcessingDetails": [
                    {"key": "Azure AD App Authentication Library", "value": ""}
                ],
                "authenticationProtocol": "none",
                "clientCredentialType": "none",
                "conditionalAccessStatus": "notApplied",
                "correlationId": "5889315c-c4ac-4807-99da-e17417eae786",
                "createdDateTime": "2023-07-26 22:58:30.983201900",
                "crossTenantAccessType": "none",
                "flaggedForReview": False,
                "id": "36658c78-02d9-4d8f-84ee-5ca4a3fdefef",
                "incomingTokenType": "none",
                "ipAddress": "12.12.12.12",
                "isInteractive": False,
                "isTenantRestricted": False,
                "location": {
                    "city": "Dublin",
                    "countryOrRegion": "IE",
                    "geoCoordinates": {
                        "latitude": 51.35555555555555,
                        "longitude": -5.244444444444444,
                    },
                    "state": "Dublin",
                },
                "managedIdentityType": "none",
                "processingTimeInMilliseconds": 0,
                "resourceDisplayName": "Azure Storage",
                "resourceId": "037694de-8c7d-498d-917d-edb650090fa5",
                "resourceServicePrincipalId": "a225221f-8cc5-411a-9cc7-5e1394b8a5b8",
                "riskDetail": "none",
                "riskLevelAggregated": "low",
                "riskLevelDuringSignIn": "none",
                "riskState": "none",
                "servicePrincipalId": "b1c34143-e405-4058-8e29-84596ad737b8",
                "servicePrincipalName": "some-service-principal",
                "status": {"errorCode": 7000215},
                "tokenIssuerType": "AzureAD",
                "uniqueTokenIdentifier": "NDDDDDDDDDDDDDDDDDD_DD",
            },
            "resourceid": "/tenants/c0dd2fa0-71be-4df8-b2a6-24cee7de069a/providers/Microsoft.aadiam",
            "resultsignature": "None",
            "resulttype": 7000215,
            "tenantid": "a2aa49aa-2c0c-49d2-af87-f402c421df0b",
            "time": "2023-07-26 23:00:20.889",
        },
    ),
    PantherRuleTest(
        Name="Failed Sign-In with riskLevelDuringSignIn",
        ExpectedResult=True,
        Log={
            "calleripaddress": "12.12.12.12",
            "category": "ServicePrincipalSignInLogs",
            "correlationid": "e1f237ef-6548-4172-be79-03818c04c06e",
            "durationms": 0,
            "level": 4,
            "location": "IE",
            "operationname": "Sign-in activity",
            "operationversion": 1,
            "p_event_time": "2023-07-26 23:00:20.889",
            "p_log_type": "Azure.Audit",
            "properties": {
                "appId": "cfceb902-8fab-4f8c-88ba-374d3c975c3a",
                "authenticationProcessingDetails": [
                    {"key": "Azure AD App Authentication Library", "value": ""}
                ],
                "authenticationProtocol": "none",
                "clientCredentialType": "none",
                "conditionalAccessStatus": "notApplied",
                "correlationId": "5889315c-c4ac-4807-99da-e17417eae786",
                "createdDateTime": "2023-07-26 22:58:30.983201900",
                "crossTenantAccessType": "none",
                "flaggedForReview": False,
                "id": "36658c78-02d9-4d8f-84ee-5ca4a3fdefef",
                "incomingTokenType": "none",
                "ipAddress": "12.12.12.12",
                "isInteractive": False,
                "isTenantRestricted": False,
                "location": {
                    "city": "Dublin",
                    "countryOrRegion": "IE",
                    "geoCoordinates": {
                        "latitude": 51.35555555555555,
                        "longitude": -5.244444444444444,
                    },
                    "state": "Dublin",
                },
                "managedIdentityType": "none",
                "processingTimeInMilliseconds": 0,
                "resourceDisplayName": "Azure Storage",
                "resourceId": "037694de-8c7d-498d-917d-edb650090fa5",
                "resourceServicePrincipalId": "a225221f-8cc5-411a-9cc7-5e1394b8a5b8",
                "riskDetail": "none",
                "riskLevelAggregated": "none",
                "riskLevelDuringSignIn": "high",
                "riskState": "none",
                "servicePrincipalId": "b1c34143-e405-4058-8e29-84596ad737b8",
                "servicePrincipalName": "some-service-principal",
                "status": {"errorCode": 7000215},
                "tokenIssuerType": "AzureAD",
                "uniqueTokenIdentifier": "NDDDDDDDDDDDDDDDDDD_DD",
            },
            "resourceid": "/tenants/c0dd2fa0-71be-4df8-b2a6-24cee7de069a/providers/Microsoft.aadiam",
            "resultsignature": "None",
            "resulttype": 7000215,
            "tenantid": "a2aa49aa-2c0c-49d2-af87-f402c421df0b",
            "time": "2023-07-26 23:00:20.889",
        },
    ),
    PantherRuleTest(
        Name="Failed Sign-In with riskLevelDuringSignIn and dismissed",
        ExpectedResult=False,
        Log={
            "calleripaddress": "12.12.12.12",
            "category": "ServicePrincipalSignInLogs",
            "correlationid": "e1f237ef-6548-4172-be79-03818c04c06e",
            "durationms": 0,
            "level": 4,
            "location": "IE",
            "operationname": "Sign-in activity",
            "operationversion": 1,
            "p_event_time": "2023-07-26 23:00:20.889",
            "p_log_type": "Azure.Audit",
            "properties": {
                "appId": "cfceb902-8fab-4f8c-88ba-374d3c975c3a",
                "authenticationProcessingDetails": [
                    {"key": "Azure AD App Authentication Library", "value": ""}
                ],
                "authenticationProtocol": "none",
                "clientCredentialType": "none",
                "conditionalAccessStatus": "notApplied",
                "correlationId": "5889315c-c4ac-4807-99da-e17417eae786",
                "createdDateTime": "2023-07-26 22:58:30.983201900",
                "crossTenantAccessType": "none",
                "flaggedForReview": False,
                "id": "36658c78-02d9-4d8f-84ee-5ca4a3fdefef",
                "incomingTokenType": "none",
                "ipAddress": "12.12.12.12",
                "isInteractive": False,
                "isTenantRestricted": False,
                "location": {
                    "city": "Dublin",
                    "countryOrRegion": "IE",
                    "geoCoordinates": {
                        "latitude": 51.35555555555555,
                        "longitude": -5.244444444444444,
                    },
                    "state": "Dublin",
                },
                "managedIdentityType": "none",
                "processingTimeInMilliseconds": 0,
                "resourceDisplayName": "Azure Storage",
                "resourceId": "037694de-8c7d-498d-917d-edb650090fa5",
                "resourceServicePrincipalId": "a225221f-8cc5-411a-9cc7-5e1394b8a5b8",
                "riskDetail": "none",
                "riskLevelAggregated": "none",
                "riskLevelDuringSignIn": "high",
                "riskState": "dismissed",
                "servicePrincipalId": "b1c34143-e405-4058-8e29-84596ad737b8",
                "servicePrincipalName": "some-service-principal",
                "status": {"errorCode": 7000215},
                "tokenIssuerType": "AzureAD",
                "uniqueTokenIdentifier": "NDDDDDDDDDDDDDDDDDD_DD",
            },
            "resourceid": "/tenants/c0dd2fa0-71be-4df8-b2a6-24cee7de069a/providers/Microsoft.aadiam",
            "resultsignature": "None",
            "resulttype": 7000215,
            "tenantid": "a2aa49aa-2c0c-49d2-af87-f402c421df0b",
            "time": "2023-07-26 23:00:20.889",
        },
    ),
    PantherRuleTest(
        Name="Missing RiskState",
        ExpectedResult=False,
        Log={
            "calleripaddress": "12.12.12.12",
            "category": "ServicePrincipalSignInLogs",
            "correlationid": "e1f237ef-6548-4172-be79-03818c04c06e",
            "durationms": 0,
            "level": 4,
            "location": "IE",
            "operationname": "Sign-in activity",
            "operationversion": 1,
            "p_event_time": "2023-07-26 23:00:20.889",
            "p_log_type": "Azure.Audit",
            "properties": {
                "appId": "cfceb902-8fab-4f8c-88ba-374d3c975c3a",
                "authenticationProcessingDetails": [
                    {"key": "Azure AD App Authentication Library", "value": ""}
                ],
                "authenticationProtocol": "none",
                "clientCredentialType": "none",
                "conditionalAccessStatus": "notApplied",
                "correlationId": "5889315c-c4ac-4807-99da-e17417eae786",
                "createdDateTime": "2023-07-26 22:58:30.983201900",
                "crossTenantAccessType": "none",
                "flaggedForReview": False,
                "id": "36658c78-02d9-4d8f-84ee-5ca4a3fdefef",
                "incomingTokenType": "none",
                "ipAddress": "12.12.12.12",
                "isInteractive": False,
                "isTenantRestricted": False,
                "location": {
                    "city": "Dublin",
                    "countryOrRegion": "IE",
                    "geoCoordinates": {
                        "latitude": 51.35555555555555,
                        "longitude": -5.244444444444444,
                    },
                    "state": "Dublin",
                },
                "managedIdentityType": "none",
                "processingTimeInMilliseconds": 0,
                "resourceDisplayName": "Azure Storage",
                "resourceId": "037694de-8c7d-498d-917d-edb650090fa5",
                "resourceServicePrincipalId": "a225221f-8cc5-411a-9cc7-5e1394b8a5b8",
                "riskDetail": "none",
                "riskLevelAggregated": "none",
                "riskLevelDuringSignIn": "none",
                "servicePrincipalId": "b1c34143-e405-4058-8e29-84596ad737b8",
                "servicePrincipalName": "some-service-principal",
                "status": {"errorCode": 7000215},
                "tokenIssuerType": "AzureAD",
                "uniqueTokenIdentifier": "NDDDDDDDDDDDDDDDDDD_DD",
            },
            "resourceid": "/tenants/c0dd2fa0-71be-4df8-b2a6-24cee7de069a/providers/Microsoft.aadiam",
            "resultsignature": "None",
            "resulttype": 7000215,
            "tenantid": "a2aa49aa-2c0c-49d2-af87-f402c421df0b",
            "time": "2023-07-26 23:00:20.889",
        },
    ),
]


class AzureAuditRiskLevelPassthrough(PantherRule):
    RuleID = "Azure.Audit.RiskLevelPassthrough-prototype"
    DisplayName = "Azure RiskLevel Passthrough"
    DedupPeriodMinutes = 10
    LogTypes = [LogType.Azure_Audit]
    Severity = PantherSeverity.Medium
    Description = "This detection surfaces an alert based on riskLevelAggregated, riskLevelDuringSignIn, and riskState.\nriskLevelAggregated and riskLevelDuringSignIn are only expected for Azure AD Premium P2 customers.\n"
    Reference = "https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-risk-feedback"
    Reports = {"MITRE ATT&CK": ["TA0006:T1110", "TA0001:T1078"]}
    Runbook = "There are a variety of potential responses to these sign-in risks. MSFT has provided an in-depth reference material at https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-risk-feedback\n"
    SummaryAttributes = [
        "properties:ServicePrincipalName",
        "properties:UserPrincipalName",
        "properties:ipAddress",
        "properties:riskLevelAggregated",
        "properties:riskLevelDuringSignIn",
        "properties:riskState",
    ]
    Tests = azure_audit_risk_level_passthrough_tests
    PASSTHROUGH_SEVERITIES = {"low", "medium", "high"}

    def rule(self, event):
        if not is_sign_in_event(event):
            return False
        self.IDENTIFIED_RISK_LEVEL = ""
        # Do not pass through risks marked as dismissed or remediated in AD
        if deep_get(event, "properties", "riskState", default="").lower() in [
            "dismissed",
            "remediated",
        ]:
            return False
        # check riskLevelAggregated
        for risk_type in ["riskLevelAggregated", "riskLevelDuringSignIn"]:
            if (
                deep_get(event, "properties", risk_type, default="").lower()
                in self.PASSTHROUGH_SEVERITIES
            ):
                self.IDENTIFIED_RISK_LEVEL = deep_get(event, "properties", risk_type).lower()
                return True
        return False

    def title(self, event):
        principal = actor_user(event)
        if principal is None:
            principal = "<NO_PRINCIPALNAME>"
        return f"AzureSignIn: RiskRanked Activity for Principal [{principal}]"

    def dedup(self, event):
        principal = actor_user(event)
        source_ip = event.udm("source_ip")
        if principal is None:
            principal = "<NO_PRINCIPALNAME>"
        return principal + source_ip

    def alert_context(self, event):
        a_c = azure_signin_alert_context(event)
        a_c["riskLevel"] = self.IDENTIFIED_RISK_LEVEL
        return a_c

    def severity(self, _):
        if self.IDENTIFIED_RISK_LEVEL:
            return self.IDENTIFIED_RISK_LEVEL
        return "INFO"
