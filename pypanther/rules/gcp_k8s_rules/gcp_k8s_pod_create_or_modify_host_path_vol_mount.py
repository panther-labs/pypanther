from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get, deep_walk

gcpk8_s_pot_create_or_modify_host_path_volume_mount_tests: list[RuleTest] = [
    RuleTest(
        name="Pod With Suspicious Volume Mount Created",
        expected_result=True,
        log={
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "some.user@company.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "io.k8s.core.v1.pods.create",
                        "resource": "core/v1/namespaces/default/pods/test",
                    },
                ],
                "methodName": "io.k8s.core.v1.pods.create",
                "request": {
                    "@type": "core.k8s.io/v1.Pod",
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "test", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {
                                "image": "nginx",
                                "imagePullPolicy": "Always",
                                "name": "test",
                                "volumeMounts": [{"mountPath": "/test", "name": "test-volume"}],
                            },
                        ],
                        "volumes": [
                            {
                                "hostPath": {"path": "/var/lib/kubelet", "type": "DirectoryOrCreate"},
                                "name": "test-volume",
                            },
                        ],
                    },
                },
                "requestMetadata": {
                    "callerIP": "1.2.3.4",
                    "callerSuppliedUserAgent": "kubectl/v1.28.2 (darwin/amd64) kubernetes/89a4ea3",
                },
                "resourceName": "core/v1/namespaces/default/pods/test",
                "response": {
                    "spec": {
                        "containers": [
                            {
                                "image": "nginx",
                                "imagePullPolicy": "Always",
                                "name": "test",
                                "volumeMounts": [{"mountPath": "/test", "name": "test-volume"}],
                            },
                        ],
                        "volumes": [
                            {
                                "hostPath": {"path": "/var/lib/kubelet", "type": "DirectoryOrCreate"},
                                "name": "test-volume",
                            },
                        ],
                    },
                    "status": {"phase": "Pending", "qosClass": "BestEffort"},
                },
            },
            "receiveTimestamp": "2024-02-16 11:48:43.531373988",
            "resource": {
                "labels": {
                    "cluster_name": "some-project-cluster",
                    "location": "us-west1",
                    "project_id": "some-project",
                },
                "type": "k8s_cluster",
            },
            "timestamp": "2024-02-16 11:48:22.742154000",
        },
    ),
    RuleTest(
        name="Pod With Non-Suspicious Volume Mount Created",
        expected_result=False,
        log={
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "some.user@company.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "io.k8s.core.v1.pods.create",
                        "resource": "core/v1/namespaces/default/pods/test",
                    },
                ],
                "methodName": "io.k8s.core.v1.pods.create",
                "request": {
                    "@type": "core.k8s.io/v1.Pod",
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "test", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {
                                "image": "nginx",
                                "imagePullPolicy": "Always",
                                "name": "test",
                                "volumeMounts": [{"mountPath": "/test", "name": "test-volume"}],
                            },
                        ],
                        "volumes": [
                            {"hostPath": {"path": "/data", "type": "DirectoryOrCreate"}, "name": "test-volume"},
                        ],
                    },
                },
                "requestMetadata": {
                    "callerIP": "1.2.3.4",
                    "callerSuppliedUserAgent": "kubectl/v1.28.2 (darwin/amd64) kubernetes/89a4ea3",
                },
                "resourceName": "core/v1/namespaces/default/pods/test",
                "response": {
                    "spec": {
                        "containers": [
                            {
                                "image": "nginx",
                                "imagePullPolicy": "Always",
                                "name": "test",
                                "volumeMounts": [{"mountPath": "/test", "name": "test-volume"}],
                            },
                        ],
                        "volumes": [
                            {"hostPath": {"path": "/data", "type": "DirectoryOrCreate"}, "name": "test-volume"},
                        ],
                    },
                    "status": {"phase": "Pending", "qosClass": "BestEffort"},
                },
            },
            "receiveTimestamp": "2024-02-16 11:48:43.531373988",
            "resource": {
                "labels": {
                    "cluster_name": "some-project-cluster",
                    "location": "us-west1",
                    "project_id": "some-project",
                },
                "type": "k8s_cluster",
            },
            "timestamp": "2024-02-16 11:48:22.742154000",
        },
    ),
    RuleTest(
        name="Pod Not Created",
        expected_result=False,
        log={
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "some.user@company.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "io.k8s.core.v1.pods.create",
                        "resource": "core/v1/namespaces/default/pods/test",
                    },
                ],
                "methodName": "io.k8s.core.v1.pods.create",
                "request": {
                    "@type": "core.k8s.io/v1.Pod",
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "test", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {
                                "image": "nginx",
                                "imagePullPolicy": "Always",
                                "name": "test",
                                "volumeMounts": [{"mountPath": "/test", "name": "test-volume"}],
                            },
                        ],
                        "volumes": [
                            {
                                "hostPath": {"path": "/var/lib/kubelet", "type": "DirectoryOrCreate"},
                                "name": "test-volume",
                            },
                        ],
                    },
                    "status": {},
                },
                "resourceName": "core/v1/namespaces/default/pods/test",
                "response": {"status": "Failure"},
            },
            "receiveTimestamp": "2024-02-16 12:55:17.003485190",
            "resource": {
                "labels": {
                    "cluster_name": "some-project-cluster",
                    "location": "us-west1",
                    "project_id": "some-project",
                },
                "type": "k8s_cluster",
            },
            "timestamp": "2024-02-16 12:55:00.510160000",
        },
    ),
]


@panther_managed
class GCPK8SPotCreateOrModifyHostPathVolumeMount(Rule):
    id = "GCP.K8S.Pot.Create.Or.Modify.Host.Path.Volume.Mount-prototype"
    display_name = "GCP K8S Pot Create Or Modify Host Path Volume Mount"
    log_types = [LogType.GCP_AUDIT_LOG]
    default_severity = Severity.HIGH
    default_description = "This detection monitors for pod creation with a hostPath volume mount. The attachment to a node's volume can allow for privilege escalation through underlying vulnerabilities or it can open up possibilities for data exfiltration or unauthorized file access. It is very rare to see this being a pod requirement.\n"
    default_runbook = "Investigate the reason of adding hostPath volume mount. Advise that it is discouraged practice. Create ticket if appropriate.\n"
    default_reference = "https://linuxhint.com/kubernetes-hostpath-volumes/"
    reports = {"MITRE ATT&CK": ["TA0001", "TA0002"]}
    tests = gcpk8_s_pot_create_or_modify_host_path_volume_mount_tests
    SUSPICIOUS_PATHS = [
        "/var/run/docker.sock",
        "/var/run/crio/crio.sock",
        "/var/lib/kubelet",
        "/var/lib/kubelet/pki",
        "/var/lib/docker/overlay2",
        "/etc/kubernetes",
        "/etc/kubernetes/manifests",
        "/etc/kubernetes/pki",
        "/home/admin",
    ]

    def rule(self, event):
        if deep_get(event, "protoPayload", "response", "status") == "Failure":
            return False
        if deep_get(event, "protoPayload", "methodName") not in (
            "io.k8s.core.v1.pods.create",
            "io.k8s.core.v1.pods.update",
            "io.k8s.core.v1.pods.patch",
        ):
            return False
        volume_mount_path = deep_walk(event, "protoPayload", "request", "spec", "volumes", "hostPath", "path")
        if not volume_mount_path or (
            volume_mount_path not in self.SUSPICIOUS_PATHS
            and (not any(path in self.SUSPICIOUS_PATHS for path in volume_mount_path))
        ):
            return False
        authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if (
                auth.get("permission")
                in ("io.k8s.core.v1.pods.create", "io.k8s.core.v1.pods.update", "io.k8s.core.v1.pods.patch")
                and auth.get("granted") is True
            ):
                return True
        return False

    def title(self, event):
        actor = deep_get(event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        pod_name = deep_get(event, "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
        project_id = deep_get(event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: [{actor}] created k8s pod [{pod_name}] with a hostPath volume mount in project [{project_id}]"

    def alert_context(self, event):
        context = gcp_alert_context(event)
        volume_mount_path = deep_walk(event, "protoPayload", "request", "spec", "volumes", "hostPath", "path")
        context["volume_mount_path"] = volume_mount_path
        return context
