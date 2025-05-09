from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.azuresignin import actor_user, azure_signin_alert_context, is_sign_in_event


@panther_managed
class AzureAuditManyFailedSignIns(Rule):
    id = "Azure.Audit.ManyFailedSignIns-prototype"
    display_name = "Azure Many Failed SignIns"
    threshold = 10
    dedup_period_minutes = 10
    log_types = [LogType.AZURE_AUDIT]
    default_severity = Severity.MEDIUM
    default_description = (
        "This detection looks for a number of failed sign-ins for the same ServicePrincipalName or UserPrincipalName\n"
    )
    reports = {"MITRE ATT&CK": ["TA0006:T1110", "TA0001:T1078"]}
    default_runbook = "Querying Sign-In logs for the ServicePrincipalName or UserPrincipalName may indicate that the principal is under attack, or that a sign-in credential rolled and some user of the credential didn't get updated.\n"
    default_reference = "https://learn.microsoft.com/en-us/entra/identity/authentication/overview-authentication"
    summary_attributes = ["properties:ServicePrincipalName", "properties:UserPrincipalName", "properties:ipAddress"]

    def rule(self, event):
        if not is_sign_in_event(event):
            return False
        error_code = event.deep_get("properties", "status", "errorCode", default=0)
        return error_code > 0

    def title(self, event):
        principal = actor_user(event)
        if principal is None:
            principal = "<NO_PRINCIPALNAME>"
        return f"AzureSignIn: Multiple Failed LogIns for Principal [{principal}]"

    def dedup(self, event):
        principal = actor_user(event)
        if principal is None:
            principal = "<NO_PRINCIPALNAME>"
        return principal

    def alert_context(self, event):
        return azure_signin_alert_context(event)

    tests = [
        RuleTest(
            name="Failed Sign-In",
            expected_result=True,
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
            name="Successful Sign-In",
            expected_result=False,
            log={
                "calleripaddress": "12.12.12.12",
                "category": "ServicePrincipalSignInLogs",
                "correlationid": "bf12205b-eea0-43dd-ad6d-b9030dc62a7a",
                "durationms": 0,
                "level": 4,
                "location": "US",
                "operationname": "Sign-in activity",
                "operationversion": 1,
                "p_log_type": "Azure.Audit",
                "properties": {
                    "appId": "3b245ca3-dcce-4a54-a070-49ad8de02963",
                    "authenticationProcessingDetails": [
                        {
                            "key": "Azure AD App Authentication Library",
                            "value": "Family: Unknown Library: Unknown 1.0.0 Platform: Unknown",
                        },
                    ],
                    "authenticationProtocol": "none",
                    "clientCredentialType": "none",
                    "conditionalAccessStatus": "notApplied",
                    "correlationId": "52d1e530-786c-443c-8dc8-aa7b1317608e",
                    "createdDateTime": "2023-07-27 13:59:53.691680300",
                    "crossTenantAccessType": "none",
                    "flaggedForReview": False,
                    "id": "55270060-d8fe-435e-9bf2-219a1d456b60",
                    "incomingTokenType": "none",
                    "ipAddress": "12.12.12.12",
                    "isInteractive": False,
                    "isTenantRestricted": False,
                    "location": {
                        "city": "Springfield",
                        "countryOrRegion": "US",
                        "geoCoordinates": {"latitude": 42.73333333333333, "longitude": -110.88888888888889},
                        "state": "Oregon",
                    },
                    "managedIdentityType": "none",
                    "processingTimeInMilliseconds": 0,
                    "resourceDisplayName": "Office 365 Management APIs",
                    "resourceId": "9cc31481-8822-49ff-b638-552ecc26c777",
                    "resourceServicePrincipalId": "2acf8174-5e07-4ec4-9de8-08d880129ba5",
                    "riskDetail": "none",
                    "riskLevelAggregated": "low",
                    "riskLevelDuringSignIn": "low",
                    "riskState": "none",
                    "servicePrincipalCredentialKeyId": "2afc776a-4e79-4588-b2ad-f62c94d6bea8",
                    "servicePrincipalId": "4b6986ec-c49c-40c0-89ce-b2ac51213e39",
                    "servicePrincipalName": "very-normal-service-principal",
                    "status": {"errorCode": 0},
                    "tokenIssuerType": "AzureAD",
                    "uniqueTokenIdentifier": "CXXXXXXXXXXXXXXXXXXXXX",
                },
                "resourceid": "/tenants/60641ed1-32f7-4a2e-a912-d724c497e1e9/providers/Microsoft.aadiam",
                "resultsignature": "None",
                "resulttype": 0,
                "tenantid": "85e54ec3-85ee-4b03-9e3b-863075eb9b62",
                "time": "2023-07-27 14:00:41.848",
            },
        ),
    ]
