from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get, deep_walk

gcpk8_s_service_type_node_port_deployed_tests: list[RuleTest] = [
    RuleTest(
        name="Service Created",
        expected_result=True,
        log={
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "some.user@company.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "io.k8s.core.v1.services.create",
                        "resource": "core/v1/namespaces/default/services/test-ns",
                    },
                ],
                "methodName": "io.k8s.core.v1.services.create",
                "request": {
                    "@type": "core.k8s.io/v1.Service",
                    "apiVersion": "v1",
                    "kind": "Service",
                    "spec": {
                        "ports": [{"name": "5678-8080", "port": 5678, "protocol": "TCP", "targetPort": 8080}],
                        "type": "NodePort",
                    },
                },
                "requestMetadata": {
                    "callerIP": "1.2.3.4",
                    "callerSuppliedUserAgent": "kubectl/v1.28.2 (darwin/amd64) kubernetes/89a4ea3",
                },
                "resourceName": "core/v1/namespaces/default/services/test-ns",
                "response": {
                    "@type": "core.k8s.io/v1.Service",
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": {
                        "creationTimestamp": "2024-02-19T12:02:21Z",
                        "name": "test-ns",
                        "namespace": "default",
                        "resourceVersion": "15036073",
                        "uid": "28758fe1-534a-4705-bcc2-12eeac6f11a4",
                    },
                    "spec": {
                        "clusterIP": "2.3.4.5",
                        "clusterIPs": ["2.3.4.5"],
                        "ports": [
                            {
                                "name": "5678-8080",
                                "nodePort": 32361,
                                "port": 5678,
                                "protocol": "TCP",
                                "targetPort": 8080,
                            },
                        ],
                        "type": "NodePort",
                    },
                },
                "serviceName": "k8s.io",
                "status": {},
            },
            "receiveTimestamp": "2024-02-19 12:02:39.542633547",
            "resource": {
                "labels": {
                    "cluster_name": "some-project-cluster",
                    "location": "us-west1",
                    "project_id": "some-project",
                },
                "type": "k8s_cluster",
            },
            "timestamp": "2024-02-19 12:02:22.057586000",
        },
    ),
    RuleTest(
        name="Error Creating Service",
        expected_result=False,
        log={
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "some.user@company.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "io.k8s.core.v1.services.create",
                        "resource": "core/v1/namespaces/default/services/test-ns",
                    },
                ],
                "methodName": "io.k8s.core.v1.services.create",
                "request": {
                    "@type": "core.k8s.io/v1.Service",
                    "apiVersion": "v1",
                    "kind": "Service",
                    "spec": {
                        "ports": [{"name": "5678-8080", "port": 5678, "protocol": "TCP", "targetPort": 8080}],
                        "type": "NodePort",
                    },
                },
                "requestMetadata": {
                    "callerIP": "1.2.3.4",
                    "callerSuppliedUserAgent": "kubectl/v1.28.2 (darwin/amd64) kubernetes/89a4ea3",
                },
                "resourceName": "core/v1/namespaces/default/services/test-ns",
                "response": {
                    "@type": "core.k8s.io/v1.Status",
                    "apiVersion": "v1",
                    "code": 409,
                    "details": {"kind": "services", "name": "test-ns"},
                    "kind": "Status",
                    "message": 'services "test-ns" already exists',
                    "metadata": {},
                    "reason": "AlreadyExists",
                    "status": "Failure",
                },
                "serviceName": "k8s.io",
                "status": {"code": 10, "message": 'services "test-ns" already exists'},
            },
            "receiveTimestamp": "2024-02-20 13:47:46.955496128",
            "resource": {
                "labels": {
                    "cluster_name": "some-project-cluster",
                    "location": "us-west1",
                    "project_id": "some-project",
                },
                "type": "k8s_cluster",
            },
            "timestamp": "2024-02-20 13:47:43.126037000",
        },
    ),
    RuleTest(
        name="No Permission Granted",
        expected_result=False,
        log={
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "some.user@company.com"},
                "authorizationInfo": [
                    {
                        "granted": False,
                        "permission": "io.k8s.core.v1.services.create",
                        "resource": "core/v1/namespaces/default/services/test-ns",
                    },
                ],
                "methodName": "io.k8s.core.v1.services.create",
                "request": {
                    "@type": "core.k8s.io/v1.Service",
                    "apiVersion": "v1",
                    "kind": "Service",
                    "spec": {
                        "ports": [{"name": "5678-8080", "port": 5678, "protocol": "TCP", "targetPort": 8080}],
                        "type": "NodePort",
                    },
                },
                "requestMetadata": {
                    "callerIP": "1.2.3.4",
                    "callerSuppliedUserAgent": "kubectl/v1.28.2 (darwin/amd64) kubernetes/89a4ea3",
                },
                "resourceName": "core/v1/namespaces/default/services/test-ns",
                "spec": {
                    "clusterIP": "2.3.4.5",
                    "clusterIPs": ["2.3.4.5"],
                    "externalTrafficPolicy": "Cluster",
                    "internalTrafficPolicy": "Cluster",
                    "ipFamilies": ["IPv4"],
                    "ipFamilyPolicy": "SingleStack",
                    "ports": [
                        {"name": "5678-8080", "nodePort": 32361, "port": 5678, "protocol": "TCP", "targetPort": 8080},
                    ],
                    "type": "NodePort",
                },
            },
            "serviceName": "k8s.io",
            "status": {},
            "receiveTimestamp": "2024-02-19 12:02:39.542633547",
            "resource": {
                "labels": {
                    "cluster_name": "some-project-cluster",
                    "location": "us-west1",
                    "project_id": "some-project",
                },
                "type": "k8s_cluster",
            },
            "timestamp": "2024-02-19 12:02:22.057586000",
        },
    ),
]


@panther_managed
class GCPK8SServiceTypeNodePortDeployed(Rule):
    id = "GCP.K8S.Service.Type.NodePort.Deployed-prototype"
    display_name = "GCP K8S Service Type NodePort Deployed"
    log_types = [LogType.GCP_AUDIT_LOG]
    default_severity = Severity.HIGH
    default_description = "This detection monitors for any kubernetes service deployed with type node port. A Node Port service allows an attacker to expose a set of pods hosting the service to the internet by opening their port and redirecting traffic here. This can be used to bypass network controls and intercept traffic, creating a direct line to the outside network.\n"
    default_runbook = "Investigate the reason of creating NodePort service. Advise that it is discouraged practice. Create ticket if appropriate.\n"
    default_reference = "https://kubernetes.io/docs/tutorials/kubernetes-basics/expose/expose-intro/"
    reports = {"MITRE ATT&CK": ["T1190"]}
    tests = gcpk8_s_service_type_node_port_deployed_tests

    def rule(self, event):
        if deep_get(event, "protoPayload", "response", "status") == "Failure":
            return False
        if deep_get(event, "protoPayload", "methodName") != "io.k8s.core.v1.services.create":
            return False
        if deep_get(event, "protoPayload", "request", "spec", "type") != "NodePort":
            return False
        authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if auth.get("permission") == "io.k8s.core.v1.services.create" and auth.get("granted") is True:
                return True
        return False

    def title(self, event):
        actor = deep_get(event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        project_id = deep_get(event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: [{actor}] created NodePort service in project [{project_id}]"

    def alert_context(self, event):
        context = gcp_alert_context(event)
        request_spec = deep_walk(event, "protoPayload", "request", "spec")
        context["request_spec"] = request_spec
        return context
