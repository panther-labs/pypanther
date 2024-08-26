from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get

gcpia_mservice_accountssign_blob_tests: list[RuleTest] = [
    RuleTest(
        name="iam.serviceAccounts.signBlob granted",
        expected_result=True,
        log={
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
                    {"permission": "iam.serviceAccounts.signBlob", "granted": True, "resourceAttributes": {}},
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
        name="iam.serviceAccounts.signBlob not granted",
        expected_result=False,
        log={
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
                    {"permission": "iam.serviceAccounts.signBlob", "granted": False, "resourceAttributes": {}},
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


@panther_managed
class GCPIAMserviceAccountssignBlob(Rule):
    id = "GCP.IAM.serviceAccounts.signBlob-prototype"
    display_name = "GCP IAM serviceAccounts signBlob"
    log_types = [LogType.GCP_AUDIT_LOG]
    reports = {"MITRE ATT&CK": ["TA0004:T1548"]}
    default_severity = Severity.HIGH
    default_description = 'The iam.serviceAccounts.signBlob permission "allows signing of arbitrary payloads" in GCP. This means we can create a signed blob that requests an access token from the Service Account we are targeting.'
    default_reference = "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
    tests = gcpia_mservice_accountssign_blob_tests

    def rule(self, event):
        authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if auth.get("permission") == "iam.serviceAccounts.signBlob" and auth.get("granted") is True:
                return True
        return False

    def title(self, event):
        actor = deep_get(event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        operation = deep_get(event, "protoPayload", "methodName", default="<OPERATION_NOT_FOUND>")
        project_id = deep_get(event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: [{actor}] performed [{operation}] on project [{project_id}]"

    def alert_context(self, event):
        return gcp_alert_context(event)
