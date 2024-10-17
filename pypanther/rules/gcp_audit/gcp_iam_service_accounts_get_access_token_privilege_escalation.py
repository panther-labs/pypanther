from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPIAMserviceAccountsgetAccessTokenPrivilegeEscalation(Rule):
    id = "GCP.IAM.serviceAccounts.getAccessToken.Privilege.Escalation-prototype"
    display_name = "GCP IAM serviceAccounts getAccessToken Privilege Escalation"
    log_types = [LogType.GCP_AUDIT_LOG]
    reports = {"MITRE ATT&CK": ["TA0004:T1548"]}
    default_severity = Severity.HIGH
    default_description = "The Identity and Access Management (IAM) service manages authorization and authentication for a GCP environment. This means that there are very likely multiple privilege escalation methods that use the IAM service and/or its permissions."
    default_reference = "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"

    def rule(self, event):
        authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if auth.get("permission") == "iam.serviceAccounts.getAccessToken" and auth.get("granted") is True:
                return True
        return False

    def title(self, event):
        actor = event.udm("actor_user")
        operation = event.deep_get("protoPayload", "methodName", default="<OPERATION_NOT_FOUND>")
        project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: [{actor}] performed [{operation}] on project [{project_id}]"

    def alert_context(self, event):
        return gcp_alert_context(event)

    tests = [
        RuleTest(
            name="iam.serviceAccounts.getAccessToken granted",
            expected_result=True,
            log={
                "p_log_type": "GCP.AuditLog",
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
                        {"permission": "iam.serviceAccounts.getAccessToken", "granted": True, "resourceAttributes": {}},
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
        RuleTest(
            name="iam.serviceAccounts.getAccessToken not granted",
            expected_result=False,
            log={
                "p_log_type": "GCP.AuditLog",
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
                        },
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
        RuleTest(
            name="Principal Subject Used",
            expected_result=True,
            log={
                "p_log_type": "GCP.AuditLog",
                "insertId": "1dy9ihte4iyjz",
                "logName": "projects/mylogs/logs/cloudaudit.googleapis.com%2Fdata_access",
                "operation": {
                    "first": True,
                    "id": "10172500524907939495",
                    "last": True,
                    "producer": "\xadiamcredentials.googleapis.com",
                },
                "protoPayload": {
                    "at_sign_type": "\xadtype.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {
                        "principalSubject": "example_principal_subject",
                        "serviceAccountDelegationInfo": [{}],
                    },
                    "authorizationInfo": [
                        {"granted": True, "permission": "iam.serviceAccounts.getAccessToken", "resourceAttributes": {}},
                    ],
                    "metadata": {
                        "identityDelegationChain": ["projects/-/serviceAccounts/xxxxx.iam.gserviceaccount.com"],
                    },
                    "methodName": "GenerateAccessToken",
                    "request": {
                        "@type": "\xadtype.googleapis.com/google.iam.credentials.v1.GenerateAccessTokenRequest",
                        "name": "projects/-/serviceAccounts/xxxxx.iam.gserviceaccount.com",
                    },
                    "requestMetadata": {
                        "callerIP": "gce-internal-ip",
                        "callerSuppliedUserAgent": "google-api-go-client/0.5 gke-metadata-server,gzip(gfe)",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2024-08-29T19:30:36.353462175Z"},
                    },
                    "resourceName": "projects/-/serviceAccounts/11111222223333444455",
                    "serviceName": "\xadiamcredentials.googleapis.com",
                    "status": {},
                },
                "receiveTimestamp": "2024-08-29 19:30:36.424542070",
                "resource": {
                    "labels": {
                        "email_id": "sample@email.com",
                        "project_id": "sample_project_id",
                        "unique_id": "11111222223333444455",
                    },
                    "type": "service_account",
                },
                "severity": "INFO",
                "timestamp": "2024-08-29 19:30:36.339983306",
            },
        ),
    ]
