from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get, deep_walk

gcpia_mservice_accountssign_jwt_privilege_escalation_tests: list[RuleTest] = [
    RuleTest(
        name="JWT Signed",
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
                    {"permission": "iam.serviceAccounts.signJwt", "granted": True, "resourceAttributes": {}},
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
        name="JWT Not Signed",
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
                    {"permission": "iam.serviceAccounts.signJwt", "granted": False, "resourceAttributes": {}},
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
class GCPIAMserviceAccountssignJwtPrivilegeEscalation(Rule):
    id = "GCP.IAM.serviceAccounts.signJwt.Privilege.Escalation-prototype"
    display_name = "GCP IAM serviceAccounts.signJwt Privilege Escalation"
    log_types = [LogType.GCP_AUDIT_LOG]
    reports = {"MITRE ATT&CK": ["TA0004:T1548"]}
    default_severity = Severity.HIGH
    default_description = "Detects iam.serviceAccounts.signJwt method for privilege escalation in GCP. This method works by signing well-formed JSON web tokens (JWTs). The script for this method will sign a well-formed JWT and request a new access token belonging to the Service Account with it."
    default_runbook = "These is not a vulnerability in GCP, this is a vulnerability in how you have configured your GCP environment, so it is your responsibility to be aware of these attack vectors and to defend against them. Make sure to follow the principle of least-privilege in your environments to help mitigate these security risks."
    default_reference = "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
    tests = gcpia_mservice_accountssign_jwt_privilege_escalation_tests

    def rule(self, event):
        if deep_get(event, "protoPayload", "methodName") != "SignJwt":
            return False
        authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if auth.get("permission") == "iam.serviceAccounts.signJwt" and auth.get("granted") is True:
                return True
        return False

    def title(self, event):
        actor = deep_get(event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        operation = deep_get(event, "protoPayload", "methodName", default="<OPERATION_NOT_FOUND>")
        project_id = deep_get(event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: [{actor}] performed [{operation}] on project [{project_id}]"

    def alert_context(self, event):
        context = gcp_alert_context(event)
        context["serviceAccountKeyName"] = deep_get(
            event,
            "protoPayload",
            "authenticationInfo",
            "serviceAccountKeyName",
        )
        return context
