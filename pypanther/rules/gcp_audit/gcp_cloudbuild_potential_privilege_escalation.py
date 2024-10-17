from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPCloudBuildPotentialPrivilegeEscalation(Rule):
    log_types = [LogType.GCP_AUDIT_LOG]
    default_description = "Detects privilege escalation attacks designed to gain access to the Cloud Build Service Account. A user with permissions to start a new build with Cloud Build can gain access to the Cloud Build Service Account and abuse it for more access to the environment."
    display_name = "GCP CloudBuild Potential Privilege Escalation"
    id = "GCP.CloudBuild.Potential.Privilege.Escalation-prototype"
    default_reference = "https://rhinosecuritylabs.com/gcp/iam-privilege-escalation-gcp-cloudbuild/"
    default_runbook = "Confirm this was authorized and necessary behavior. To defend against this privilege escalation attack, it is necessary to restrict the permissions granted to the Cloud Build Service Account and to be careful granting the cloudbuild.builds.create permission to any users in your Organization. Most importantly, you need to know that any user who is granted cloudbuild.builds.create, is also indirectly granted all the permissions granted to the Cloud Build Service Account. If that’s alright with you, then you may not need to worry about this attack vector, but it is still highly recommended to modify the default permissions granted to the Cloud Build Service Account."
    reports = {"MITRE ATT&CK": ["TA0004:T1548"]}
    default_severity = Severity.HIGH

    def rule(self, event):
        if not event.deep_get("protoPayload", "methodName", default="METHOD_NOT_FOUND").endswith(
            "CloudBuild.CreateBuild",
        ):
            return False
        authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if auth.get("permission") == "cloudbuild.builds.create" and auth.get("granted") is True:
                return True
        return False

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        operation = event.deep_get("protoPayload", "methodName", default="<OPERATION_NOT_FOUND>")
        project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: [{actor}] performed [{operation}] on project [{project_id}]"

    def alert_context(self, event):
        return gcp_alert_context(event)

    tests = [
        RuleTest(
            name="GCP CloudBuild - Build with Potentially Privileged Access",
            expected_result=True,
            log={
                "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
                "operation": {
                    "first": True,
                    "id": "operations/build/some-project/YzNhZWI0YWYtNjAwNi00YzM5LTgxYmUtMjhmMjc1YzJkOGEz",
                    "producer": "cloudbuild.googleapis.com",
                },
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {
                        "principalEmail": "whodoneit@some-project.iam.gserviceaccount.com",
                        "principalSubject": "serviceAccount:whodoneit@some-project.iam.gserviceaccount.com",
                        "serviceAccountKeyName": "//iam.googleapis.com/projects/some-project/serviceAccounts/whodoneit@some-project.iam.gserviceaccount.com/keys/123er456788",
                    },
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "cloudbuild.builds.create",
                            "resource": "projects/some-project",
                            "resourceAttributes": {},
                        },
                    ],
                    "methodName": "google.devtools.cloudbuild.v1.CloudBuild.CreateBuild",
                    "request": {
                        "@type": "type.googleapis.com/google.devtools.cloudbuild.v1.CreateBuildRequest",
                        "build": {},
                        "projectId": "some-project",
                    },
                    "requestMetadata": {
                        "callerIP": "189.163.74.177",
                        "callerSuppliedUserAgent": "(gzip),gzip(gfe),gzip(gfe)",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2024-01-25T11:55:09.740095Z"},
                    },
                    "resourceLocation": {"currentLocations": ["global"]},
                    "resourceName": "projects/some-project/builds",
                    "serviceName": "cloudbuild.googleapis.com",
                },
                "receiveTimestamp": "2024-01-25 11:55:09.854909113",
                "resource": {
                    "labels": {
                        "build_id": "c3aeb4ap-6006-4c39-81be-28f275c2d8a3",
                        "build_trigger_id": "",
                        "project_id": "some-project",
                    },
                    "type": "build",
                },
                "severity": "NOTICE",
                "timestamp": "2024-01-25 11:55:08.919358000",
            },
        ),
        RuleTest(
            name="GCP CreateBrand - No Privileged Access",
            expected_result=False,
            log={
                "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "john.doe@some-project.com"},
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "clientauthconfig.brands.create",
                            "resource": "brands/1028347248702",
                            "resourceAttributes": {},
                        },
                    ],
                    "methodName": "CreateBrand",
                    "request": {
                        "brand": {
                            "displayName": "NewBrand",
                            "projectNumbers": ["1028345275902"],
                            "supportEmail": "john.doe@some-project.com",
                        },
                        "visibility": "INTERNAL",
                    },
                    "requestMetadata": {
                        "callerIP": "189.163.74.177",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2024-01-24T14:30:05.891336Z"},
                    },
                    "resourceName": "brands/1028347275902",
                    "response": {
                        "brandId": "1028347248702",
                        "creationTime": "2024-01-24T14:30:05.400Z",
                        "displayName": "NewBrand test",
                        "projectNumbers": ["1028347248702"],
                        "supportEmail": "some.user@company.com",
                        "updateTime": "2024-01-24T14:30:05.866002Z",
                    },
                    "serviceName": "clientauthconfig.googleapis.com",
                    "status": {},
                },
                "receiveTimestamp": "2024-01-24 14:30:06.741210353",
                "resource": {
                    "labels": {"brand_id": "1028347248702", "project_id": "some-project"},
                    "type": "client_auth_config_brand",
                },
                "severity": "NOTICE",
                "timestamp": "2024-01-24 14:30:05.207884000",
            },
        ),
    ]
