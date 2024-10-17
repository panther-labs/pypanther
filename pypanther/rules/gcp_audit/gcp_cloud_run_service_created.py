from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPCloudRunServiceCreated(Rule):
    log_types = [LogType.GCP_AUDIT_LOG]
    default_description = "Detects creation of new Cloud Run Service, which, if configured maliciously, may be part of the attack aimed to invoke the service and retrieve the access token."
    display_name = "GCP Cloud Run Service Created"
    id = "GCP.Cloud.Run.Service.Created-prototype"
    create_alert = False
    default_reference = "https://cloud.google.com/run/docs/quickstarts/deploy-container"
    default_runbook = "Confirm this was authorized and necessary behavior"
    default_severity = Severity.LOW

    def rule(self, event):
        if event.get("severity") == "ERROR":
            return False
        method_name = event.deep_get("protoPayload", "methodName", default="")
        if not method_name.endswith("Services.CreateService"):
            return False
        authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if auth.get("permission") == "run.services.create" and auth.get("granted") is True:
                return True
        return False

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: [{actor}] created new Run Service in project [{project_id}]"

    def alert_context(self, event):
        context = gcp_alert_context(event)
        context["service_account"] = event.deep_get(
            "protoPayload",
            "request",
            "service",
            "spec",
            "template",
            "spec",
            default="<SERVICE_ACCOUNT_NOT_FOUND>",
        )
        return context

    tests = [
        RuleTest(
            name="GCP No methodName found",
            expected_result=False,
            log={
                "p_event_time": "2024-07-22 14:20:56.237323088",
                "p_log_type": "GCP.AuditLog",
                "insertId": "123456789xyz",
                "logName": "projects/internal-sentry/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "0000000000000@cloudbuild.gserviceaccount.com"},
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "cloudbuild.builds.create",
                            "resource": "projects/00000000aaaaaaaa",
                            "resourceAttributes": {},
                        },
                    ],
                    "requestMetadata": {
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2024-07-22T14:20:55.898367039Z"},
                    },
                },
                "receiveTimestamp": "2024-07-22 14:20:56.428021476",
                "resource": {
                    "labels": {"method": "", "project_id": "some-project", "service": ""},
                    "type": "audited_resource",
                },
                "severity": "NOTICE",
                "timestamp": "2024-07-22 14:20:56.237323088",
            },
        ),
        RuleTest(
            name="GCP Run Service Created",
            expected_result=True,
            log={
                "insertId": "jzm5rucrn2",
                "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {
                        "principalEmail": "some.user@company.com",
                        "principalSubject": "user:some.user@company.com",
                    },
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "run.services.create",
                            "resource": "namespaces/some-project/services/cloudrun-exfil",
                            "resourceAttributes": {},
                        },
                    ],
                    "methodName": "google.cloud.run.v1.Services.CreateService",
                    "request": {
                        "@type": "type.googleapis.com/google.cloud.run.v1.CreateServiceRequest",
                        "parent": "namespaces/some-project",
                        "service": {
                            "apiVersion": "serving.knative.dev/v1",
                            "kind": "Service",
                            "metadata": {
                                "annotations": {
                                    "client.knative.dev/user-image": "us-west1-docker.pkg.dev/some-project/abc-test/run_services_create_test",
                                },
                                "name": "cloudrun-exfil",
                                "namespace": "some-project",
                            },
                            "spec": {
                                "template": {
                                    "metadata": {
                                        "annotations": {
                                            "client.knative.dev/user-image": "us-west1-docker.pkg.dev/some-project/abc-test/run_services_create_test",
                                        },
                                        "labels": {"cloud.googleapis.com/location": "us-west1"},
                                        "name": "cloudrun-exfil-00001-zif",
                                    },
                                    "spec": {"serviceAccountName": "abc-test@some-project.iam.gserviceaccount.com"},
                                },
                            },
                        },
                    },
                    "requestMetadata": {
                        "callerIP": "1.2.3.4",
                        "callerSuppliedUserAgent": "(gzip),gzip(gfe)",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2024-02-02T09:43:54.690161Z"},
                    },
                    "resourceLocation": {"currentLocations": ["us-west1"]},
                    "resourceName": "namespaces/some-project/services/cloudrun-exfil",
                    "response": {
                        "@type": "type.googleapis.com/google.cloud.run.v1.Service",
                        "apiVersion": "serving.knative.dev/v1",
                        "kind": "Service",
                        "metadata": {
                            "annotations": {
                                "client.knative.dev/user-image": "us-west1-docker.pkg.dev/some-project/abc-test/run_services_create_test",
                                "run.googleapis.com/ingress": "all",
                                "run.googleapis.com/operation-id": "6fdf115a-1bdd-4836-b0ca-ae71f8ba6718",
                                "serving.knative.dev/creator": "some.user@company.com",
                                "serving.knative.dev/lastModifier": "some.user@company.com",
                            },
                            "creationTimestamp": "2024-02-02T09:43:54.640837Z",
                            "generation": 1,
                            "labels": {"cloud.googleapis.com/location": "us-west1"},
                            "name": "cloudrun-exfil",
                            "namespace": "1028347275902",
                            "resourceVersion": "AAYQYvNHUcU",
                            "selfLink": "/apis/serving.knative.dev/v1/namespaces/1028347275902/services/cloudrun-exfil",
                            "uid": "45101e8e-7b91-4c41-81a1-969e876923f4",
                        },
                        "spec": {
                            "template": {
                                "metadata": {
                                    "annotations": {
                                        "autoscaling.knative.dev/maxScale": "100",
                                        "client.knative.dev/user-image": "us-west1-docker.pkg.dev/some-project/abc-test/run_services_create_test",
                                    },
                                    "labels": {"run.googleapis.com/startupProbeType": "Default"},
                                    "name": "cloudrun-exfil-00001-zif",
                                },
                                "spec": {
                                    "containerConcurrency": 80,
                                    "serviceAccountName": "abc-test@some-project.iam.gserviceaccount.com",
                                    "timeoutSeconds": 300,
                                },
                            },
                            "traffic": [{"latestRevision": True, "percent": 100}],
                        },
                        "status": {},
                    },
                    "serviceName": "run.googleapis.com",
                },
                "receiveTimestamp": "2024-02-02 09:43:54.723840817",
                "resource": {
                    "labels": {
                        "configuration_name": "",
                        "location": "us-west1",
                        "project_id": "some-project",
                        "revision_name": "",
                        "service_name": "cloudrun-exfil",
                    },
                    "type": "cloud_run_revision",
                },
                "severity": "NOTICE",
                "timestamp": "2024-02-02 09:43:54.497796000",
            },
        ),
        RuleTest(
            name="GCP Run Service Not Created",
            expected_result=False,
            log={
                "insertId": "jfca5rd3wqn",
                "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {
                        "principalEmail": "some.user@company.com",
                        "principalSubject": "user:some.user@company.com",
                    },
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "run.services.create",
                            "resource": "namespaces/some-project/services/cloudrun-exfil",
                            "resourceAttributes": {},
                        },
                    ],
                    "methodName": "google.cloud.run.v1.Services.CreateService",
                    "request": "...",
                    "requestMetadata": "...",
                    "resourceLocation": "...",
                    "resourceName": "...",
                    "serviceName": "run.googleapis.com",
                    "status": {"code": 6, "message": "Resource 'cloudrun-exfil' already exists."},
                },
                "receiveTimestamp": "2024-02-02 09:36:22.250430490",
                "resource": "...",
                "severity": "ERROR",
                "timestamp": "2024-02-02 09:36:21.212182000",
            },
        ),
    ]
