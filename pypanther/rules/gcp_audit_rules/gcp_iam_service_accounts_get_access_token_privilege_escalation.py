from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

gcpia_mservice_accountsget_access_token_privilege_escalation_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="iam.serviceAccounts.getAccessToken granted",
        ExpectedResult=True,
        Log={
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "status": {},
                "authenticationInfo": {
                    "principalEmail": "some-project@company.iam.gserviceaccount.com",
                    "serviceAccountKeyName": "//iam.googleapis.com/projects/some-project/serviceAccounts/some-project@company.iam.gserviceaccount.com/keys/a378358365ff3d22e9c1a72fecf4605ddff76b47",
                    "principalSubject": "serviceAccount:some-project@company.iam.gserviceaccount.com",
                },
                "requestMetadata": {
                    "callerIp": "1.2.3.4",
                    "requestAttributes": {"time": "2024-02-26T17:15:16.327542536Z", "auth": {}},
                    "destinationAttributes": {},
                },
                "serviceName": "iamcredentials.googleapis.com",
                "methodName": "SignJwt",
                "authorizationInfo": [
                    {
                        "permission": "iam.serviceAccounts.getAccessToken",
                        "granted": True,
                        "resourceAttributes": {},
                    }
                ],
                "resourceName": "projects/-/serviceAccounts/114885146936855121342",
                "request": {
                    "name": "projects/-/serviceAccounts/some-project@company.iam.gserviceaccount.com",
                    "@type": "type.googleapis.com/google.iam.credentials.v1.SignJwtRequest",
                },
            },
            "insertId": "1hu88qbef4d2o",
            "resource": {
                "type": "service_account",
                "labels": {
                    "project_id": "some-project",
                    "unique_id": "114885146936855121342",
                    "email_id": "some-project@company.iam.gserviceaccount.com",
                },
            },
            "timestamp": "2024-02-26T17:15:16.314854637Z",
            "severity": "INFO",
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Fdata_access",
            "receiveTimestamp": "2024-02-26T17:15:17.100020459Z",
        },
    ),
    PantherRuleTest(
        Name="iam.serviceAccounts.getAccessToken not granted",
        ExpectedResult=False,
        Log={
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "status": {},
                "authenticationInfo": {
                    "principalEmail": "some-project@company.iam.gserviceaccount.com",
                    "serviceAccountKeyName": "//iam.googleapis.com/projects/some-project/serviceAccounts/some-project@company.iam.gserviceaccount.com/keys/a378358365ff3d22e9c1a72fecf4605ddff76b47",
                    "principalSubject": "serviceAccount:some-project@company.iam.gserviceaccount.com",
                },
                "requestMetadata": {
                    "callerIp": "1.2.3.4",
                    "requestAttributes": {"time": "2024-02-26T17:15:16.327542536Z", "auth": {}},
                    "destinationAttributes": {},
                },
                "serviceName": "iamcredentials.googleapis.com",
                "methodName": "SignJwt",
                "authorizationInfo": [
                    {
                        "permission": "iam.serviceAccounts.getAccessToken",
                        "granted": False,
                        "resourceAttributes": {},
                    }
                ],
                "resourceName": "projects/-/serviceAccounts/114885146936855121342",
                "request": {
                    "name": "projects/-/serviceAccounts/some-project@company.iam.gserviceaccount.com",
                    "@type": "type.googleapis.com/google.iam.credentials.v1.SignJwtRequest",
                },
            },
            "insertId": "1hu88qbef4d2o",
            "resource": {
                "type": "service_account",
                "labels": {
                    "project_id": "some-project",
                    "unique_id": "114885146936855121342",
                    "email_id": "some-project@company.iam.gserviceaccount.com",
                },
            },
            "timestamp": "2024-02-26T17:15:16.314854637Z",
            "severity": "INFO",
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Fdata_access",
            "receiveTimestamp": "2024-02-26T17:15:17.100020459Z",
        },
    ),
]


class GCPIAMserviceAccountsgetAccessTokenPrivilegeEscalation(PantherRule):
    RuleID = "GCP.IAM.serviceAccounts.getAccessToken.Privilege.Escalation-prototype"
    DisplayName = "GCP IAM serviceAccounts getAccessToken Privilege Escalation"
    LogTypes = [LogType.GCP_AuditLog]
    Reports = {"MITRE ATT&CK": ["TA0004:T1548"]}
    Severity = PantherSeverity.High
    Description = "The Identity and Access Management (IAM) service manages authorization and authentication for a GCP environment. This means that there are very likely multiple privilege escalation methods that use the IAM service and/or its permissions."
    Reference = (
        "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
    )
    Tests = gcpia_mservice_accountsget_access_token_privilege_escalation_tests

    def rule(self, event):
        authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if (
                auth.get("permission") == "iam.serviceAccounts.getAccessToken"
                and auth.get("granted") is True
            ):
                return True
        return False

    def title(self, event):
        actor = deep_get(
            event,
            "protoPayload",
            "authenticationInfo",
            "principalEmail",
            default="<ACTOR_NOT_FOUND>",
        )
        operation = deep_get(event, "protoPayload", "methodName", default="<OPERATION_NOT_FOUND>")
        project_id = deep_get(
            event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>"
        )
        return f"[GCP]: [{actor}] performed [{operation}] on project [{project_id}]"

    def alert_context(self, event):
        return gcp_alert_context(event)
