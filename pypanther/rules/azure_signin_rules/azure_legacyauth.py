import json
from unittest.mock import MagicMock

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_azuresignin_helpers import actor_user, azure_signin_alert_context, is_sign_in_event
from pypanther.helpers.panther_base_helpers import deep_get

azure_audit_legacy_auth_tests: list[RuleTest] = [
    RuleTest(
        name="Failed Sign-In",
        expected_result=False,
        log={
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
                "authenticationProcessingDetails": [{"key": "Azure AD App Authentication Library", "value": ""}],
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
                    "geoCoordinates": {"latitude": 51.35555555555555, "longitude": -5.244444444444444},
                    "state": "Dublin",
                },
                "managedIdentityType": "none",
                "processingTimeInMilliseconds": 0,
                "resourceDisplayName": "Azure Storage",
                "resourceId": "037694de-8c7d-498d-917d-edb650090fa5",
                "resourceServicePrincipalId": "a225221f-8cc5-411a-9cc7-5e1394b8a5b8",
                "riskDetail": "none",
                "riskLevelAggregated": "low",
                "riskLevelDuringSignIn": "low",
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
    RuleTest(
        name="Sign-In with legacy auth",
        expected_result=True,
        log={
            "calleripaddress": "173.53.70.163",
            "category": "SignInLogs",
            "correlationid": "1043d312-230b-4f85-89de-2438df7ad2e9",
            "durationms": 0,
            "identity": "Some Identity",
            "level": 4,
            "location": "US",
            "operationname": "Sign-in activity",
            "operationversion": 1,
            "p_event_time": "2023-07-21 05:05:12.056",
            "p_log_type": "Azure.Audit",
            "properties": {
                "appDisplayName": "Office 365 Exchange Online",
                "appId": "975c4feb-8c6b-4ed8-82e2-f0952ecc64d4",
                "appliedConditionalAccessPolicies": [],
                "authenticationContextClassReferences": [],
                "authenticationDetails": [
                    {
                        "authenticationMethod": "Password",
                        "authenticationMethodDetail": "Password in the cloud",
                        "authenticationStepDateTime": "2023-01-11T11:11:11",
                        "authenticationStepRequirement": "",
                        "authenticationStepResultDetail": "Correct password",
                        "succeeded": True,
                    },
                ],
                "authenticationProcessingDetails": [],
                "authenticationProtocol": "rpoc",
                "authenticationRequirement": "singleFactorAuthentication",
                "authenticationRequirementPolicies": [],
                "authenticationStrengths": [],
                "autonomousSystemNumber": 1234,
                "clientAppUsed": "Authenticated SMTP",
                "clientCredentialType": "clientAssertion",
                "conditionalAccessStatus": "notApplied",
                "correlationId": "9d5f7dd3-46a7-475a-9cc3-96160551ce49",
                "createdDateTime": "2023-07-21 05:03:52.160562400",
                "crossTenantAccessType": "none",
                "deviceDetail": {"deviceId": "", "displayName": "", "operatingSystem": "MacOs"},
                "flaggedForReview": False,
                "homeTenantId": "4328f0a8-06da-4457-b0d0-2c8e115e52cc",
                "id": "d9ae0e20-c959-42a3-ba74-00f59ac9f6c6",
                "incomingTokenType": "none",
                "ipAddress": "12.12.12.12",
                "isInteractive": True,
                "isTenantRestricted": False,
                "location": {
                    "city": "Springfield",
                    "countryOrRegion": "US",
                    "geoCoordinates": {"latitude": 34.55555555555555, "longitude": -74.4444444444444},
                    "state": "Virginia",
                },
                "mfaDetail": {},
                "networkLocationDetails": [],
                "originalRequestId": "51755ad1-bc0d-4694-acb2-a21f054869ab",
                "privateLinkDetails": {},
                "processingTimeInMilliseconds": 343,
                "resourceDisplayName": "Office 365 Exchange Online",
                "resourceId": "b54c474b-4d74-4920-b0c3-7a8d2f2c4e95",
                "resourceServicePrincipalId": "d8f787f8-7f22-40d4-b057-6fc59c49ca43",
                "resourceTenantId": "fc66a38e-bcba-4fe9-b2de-c67918514cc5",
                "riskDetail": "none",
                "riskEventTypes": [],
                "riskEventTypes_v2": [],
                "riskLevelAggregated": "none",
                "riskLevelDuringSignIn": "none",
                "riskState": "none",
                "rngcStatus": 0,
                "servicePrincipalId": "",
                "sessionLifetimePolicies": [],
                "ssoExtensionVersion": "",
                "status": {"additionalDetails": "MFA requirement satisfied by claim in the token", "errorCode": 0},
                "tenantId": "237c496d-1ca2-4b13-aa0f-69e44d745a27",
                "tokenIssuerName": "",
                "tokenIssuerType": "AzureAD",
                "uniqueTokenIdentifier": "hhhhhhhhhhhhhhhhhhhhhh",
                "userAgent": "BAV2ROPC",
                "userDisplayName": "A User Display Name",
                "userId": "8105c513-d24b-4b8d-9035-f8d48854d703",
                "userPrincipalName": "homer.simpson@springfield.org",
                "userType": "Member",
            },
            "resourceid": "/tenants/ef3a1b35-97d6-474b-a9de-94d21d4ee71b/providers/Microsoft.aadiam",
            "resultsignature": "None",
            "resulttype": 0,
            "tenantid": "c5fd010a-2972-4be2-9c67-986ceca2a042",
            "time": "2023-07-21 05:05:12.056",
        },
    ),
    RuleTest(
        name="Sign-In with legacy auth, KNOWN_EXCEPTION",
        expected_result=False,
        mocks=[RuleMock(object_name="KNOWN_EXCEPTIONS", return_value='[\n  "homer.simpson@springfield.org"\n]')],
        log={
            "calleripaddress": "173.53.70.163",
            "category": "SignInLogs",
            "correlationid": "1043d312-230b-4f85-89de-2438df7ad2e9",
            "durationms": 0,
            "identity": "Some Identity",
            "level": 4,
            "location": "US",
            "operationname": "Sign-in activity",
            "operationversion": 1,
            "p_event_time": "2023-07-21 05:05:12.056",
            "p_log_type": "Azure.Audit",
            "properties": {
                "appDisplayName": "Office 365 Exchange Online",
                "appId": "975c4feb-8c6b-4ed8-82e2-f0952ecc64d4",
                "appliedConditionalAccessPolicies": [],
                "authenticationContextClassReferences": [],
                "authenticationDetails": [
                    {
                        "authenticationMethod": "Password",
                        "authenticationMethodDetail": "Password in the cloud",
                        "authenticationStepDateTime": "2023-01-11T11:11:11",
                        "authenticationStepRequirement": "",
                        "authenticationStepResultDetail": "Correct password",
                        "succeeded": True,
                    },
                ],
                "authenticationProcessingDetails": [],
                "authenticationProtocol": "rpoc",
                "authenticationRequirement": "singleFactorAuthentication",
                "authenticationRequirementPolicies": [],
                "authenticationStrengths": [],
                "autonomousSystemNumber": 1234,
                "clientAppUsed": "Authenticated SMTP",
                "clientCredentialType": "clientAssertion",
                "conditionalAccessStatus": "notApplied",
                "correlationId": "9d5f7dd3-46a7-475a-9cc3-96160551ce49",
                "createdDateTime": "2023-07-21 05:03:52.160562400",
                "crossTenantAccessType": "none",
                "deviceDetail": {"deviceId": "", "displayName": "", "operatingSystem": "MacOs"},
                "flaggedForReview": False,
                "homeTenantId": "4328f0a8-06da-4457-b0d0-2c8e115e52cc",
                "id": "d9ae0e20-c959-42a3-ba74-00f59ac9f6c6",
                "incomingTokenType": "none",
                "ipAddress": "12.12.12.12",
                "isInteractive": True,
                "isTenantRestricted": False,
                "location": {
                    "city": "Springfield",
                    "countryOrRegion": "US",
                    "geoCoordinates": {"latitude": 34.55555555555555, "longitude": -74.4444444444444},
                    "state": "Virginia",
                },
                "mfaDetail": {},
                "networkLocationDetails": [],
                "originalRequestId": "51755ad1-bc0d-4694-acb2-a21f054869ab",
                "privateLinkDetails": {},
                "processingTimeInMilliseconds": 343,
                "resourceDisplayName": "Office 365 Exchange Online",
                "resourceId": "b54c474b-4d74-4920-b0c3-7a8d2f2c4e95",
                "resourceServicePrincipalId": "d8f787f8-7f22-40d4-b057-6fc59c49ca43",
                "resourceTenantId": "fc66a38e-bcba-4fe9-b2de-c67918514cc5",
                "riskDetail": "none",
                "riskEventTypes": [],
                "riskEventTypes_v2": [],
                "riskLevelAggregated": "none",
                "riskLevelDuringSignIn": "none",
                "riskState": "none",
                "rngcStatus": 0,
                "servicePrincipalId": "",
                "sessionLifetimePolicies": [],
                "ssoExtensionVersion": "",
                "status": {"additionalDetails": "MFA requirement satisfied by claim in the token", "errorCode": 0},
                "tenantId": "237c496d-1ca2-4b13-aa0f-69e44d745a27",
                "tokenIssuerName": "",
                "tokenIssuerType": "AzureAD",
                "uniqueTokenIdentifier": "hhhhhhhhhhhhhhhhhhhhhh",
                "userAgent": "BAV2ROPC",
                "userDisplayName": "A User Display Name",
                "userId": "8105c513-d24b-4b8d-9035-f8d48854d703",
                "userPrincipalName": "homer.simpson@springfield.org",
                "userType": "Member",
            },
            "resourceid": "/tenants/ef3a1b35-97d6-474b-a9de-94d21d4ee71b/providers/Microsoft.aadiam",
            "resultsignature": "None",
            "resulttype": 0,
            "tenantid": "c5fd010a-2972-4be2-9c67-986ceca2a042",
            "time": "2023-07-21 05:05:12.056",
        },
    ),
]


@panther_managed
class AzureAuditLegacyAuth(Rule):
    id = "Azure.Audit.LegacyAuth-prototype"
    display_name = "Azure SignIn via Legacy Authentication Protocol"
    dedup_period_minutes = 10
    log_types = [LogType.AZURE_AUDIT]
    default_severity = Severity.MEDIUM
    default_description = "This detection looks for Successful Logins that have used legacy authentication protocols\n"
    default_reference = (
        "https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/workbook-legacy-authentication"
    )
    default_runbook = "Based on Microsoft's analysis more than 97 percent of credential stuffing attacks use legacy authentication and more than 99 percent of password spray attacks use legacy authentication protocols. These attacks would stop with basic authentication disabled or blocked. see https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication\nIf you are aware of this Legacy Auth need, and need to continue using this mechanism, add the principal name to KNOWN_EXCEPTIONS. The Reference link contains additional material hosted on Microsoft.com\n"
    summary_attributes = ["properties:ServicePrincipalName", "properties:UserPrincipalName", "properties:ipAddress"]
    tests = azure_audit_legacy_auth_tests
    LEGACY_AUTH_USERAGENTS = ["BAV2ROPC", "CBAInPROD"]  # CBAInPROD is reported to be IMAP
    # Add ServicePrincipalName/UserPrincipalName to
    # KNOWN_EXCEPTIONS to prevent these Principals from Alerting
    KNOWN_EXCEPTIONS = []

    def rule(self, event):
        if not is_sign_in_event(event):
            return False
        if isinstance(self.KNOWN_EXCEPTIONS, MagicMock):
            self.KNOWN_EXCEPTIONS = json.loads(self.KNOWN_EXCEPTIONS())  # pylint: disable=not-callable
        if actor_user(event) in self.KNOWN_EXCEPTIONS:
            return False
        user_agent = deep_get(event, "properties", "userAgent", default="")
        error_code = deep_get(event, "properties", "status", "errorCode", default=0)
        return all([user_agent in self.LEGACY_AUTH_USERAGENTS, error_code == 0])

    def title(self, event):
        principal = actor_user(event)
        if principal is None:
            principal = "<NO_PRINCIPALNAME>"
        return f"AzureSignIn: Principal [{principal}] authenticated with a legacy auth protocol"

    def dedup(self, event):
        principal = actor_user(event)
        if principal is None:
            principal = "<NO_PRINCIPALNAME>"
        return principal

    def alert_context(self, event):
        a_c = azure_signin_alert_context(event)
        a_c["userAgent"] = deep_get(event, "properties", "userAgent", "<NO_USERAGENT>")
        return a_c
