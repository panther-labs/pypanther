from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get, deep_walk
from pypanther.log_types import LogType

gcpk8_s_privileged_pod_created_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Privileged Pod Created",
        ExpectedResult=True,
        Log={
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
            "operation": {},
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "john.doe@company.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "io.k8s.core.v1.pods.create",
                        "resource": "core/v1/namespaces/default/pods/test-privileged-pod",
                    }
                ],
                "methodName": "io.k8s.core.v1.pods.create",
                "request": {
                    "@type": "core.k8s.io/v1.Pod",
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "test-privileged-pod", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {
                                "image": "nginx",
                                "imagePullPolicy": "Always",
                                "name": "nginx",
                                "resources": {},
                                "securityContext": {"privileged": True},
                            }
                        ],
                        "securityContext": {},
                    },
                    "status": {},
                },
                "requestMetadata": {"callerIP": "1.2.3.4"},
                "resourceName": "core/v1/namespaces/default/pods/test-privileged-pod",
                "response": {
                    "@type": "core.k8s.io/v1.Pod",
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {},
                    "spec": {
                        "containers": [
                            {
                                "image": "nginx",
                                "imagePullPolicy": "Always",
                                "name": "nginx",
                                "resources": {},
                                "securityContext": {"privileged": True},
                            }
                        ],
                        "securityContext": {},
                        "serviceAccount": "default",
                        "serviceAccountName": "default",
                        "terminationGracePeriodSeconds": 30,
                    },
                    "status": {},
                },
                "serviceName": "k8s.io",
                "status": {},
            },
            "receiveTimestamp": "2024-02-13 12:45:20.058795785",
            "resource": {
                "labels": {
                    "cluster_name": "some-project-cluster",
                    "location": "us-west1",
                    "project_id": "some-project",
                },
                "type": "k8s_cluster",
            },
            "timestamp": "2024-02-13 12:45:06.073905000",
        },
    ),
    PantherRuleTest(
        Name="Run-As-Root Pod Created",
        ExpectedResult=True,
        Log={
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
            "operation": {},
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "john.doe@company.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "io.k8s.core.v1.pods.create",
                        "resource": "core/v1/namespaces/default/pods/test-runasroot-pod",
                    }
                ],
                "methodName": "io.k8s.core.v1.pods.create",
                "request": {
                    "@type": "core.k8s.io/v1.Pod",
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {},
                    "spec": {
                        "containers": [
                            {
                                "image": "nginx",
                                "imagePullPolicy": "Always",
                                "name": "nginx",
                                "resources": {},
                                "securityContext": {"runAsNonRoot": False},
                            }
                        ]
                    },
                    "status": {},
                },
                "requestMetadata": {"callerIP": "1.2.3.4"},
                "resourceName": "core/v1/namespaces/default/pods/test-runasroot-pod",
                "response": {
                    "@type": "core.k8s.io/v1.Pod",
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {},
                    "spec": {
                        "containers": [
                            {
                                "image": "nginx",
                                "imagePullPolicy": "Always",
                                "name": "nginx",
                                "resources": {},
                                "securityContext": {"runAsNonRoot": False},
                            }
                        ]
                    },
                    "status": {"phase": "Pending", "qosClass": "BestEffort"},
                },
                "serviceName": "k8s.io",
                "status": {},
            },
            "receiveTimestamp": "2024-02-13 13:13:53.113465457",
            "resource": {
                "labels": {
                    "cluster_name": "some-project-cluster",
                    "location": "us-west1",
                    "project_id": "some-project",
                },
                "type": "k8s_cluster",
            },
            "timestamp": "2024-02-13 13:13:45.363388000",
        },
    ),
    PantherRuleTest(
        Name="Non-Privileged Pod Created",
        ExpectedResult=False,
        Log={
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
            "operation": {
                "first": True,
                "id": "7f8c5bec-01ff-4079-97e3-065ac34e10e8",
                "last": True,
                "producer": "k8s.io",
            },
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "john.doe@company.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "io.k8s.core.v1.pods.create",
                        "resource": "core/v1/namespaces/default/pods/test-non-privileged-pod",
                    }
                ],
                "methodName": "io.k8s.core.v1.pods.create",
                "request": {
                    "@type": "core.k8s.io/v1.Pod",
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "test-non-privileged-pod", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {
                                "image": "nginx",
                                "imagePullPolicy": "Always",
                                "name": "nginx",
                                "resources": {},
                            }
                        ]
                    },
                    "status": {},
                },
                "requestMetadata": {"callerIP": "1.2.3.4"},
                "resourceName": "core/v1/namespaces/default/pods/test-non-privileged-pod",
                "response": {
                    "@type": "core.k8s.io/v1.Pod",
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {},
                    "spec": {
                        "containers": [
                            {
                                "image": "nginx",
                                "imagePullPolicy": "Always",
                                "name": "nginx",
                                "resources": {},
                            }
                        ]
                    },
                    "status": {},
                },
                "serviceName": "k8s.io",
                "status": {},
            },
            "receiveTimestamp": "2024-02-13 13:07:54.642331675",
            "resource": {
                "labels": {
                    "cluster_name": "some-project-cluster",
                    "location": "us-west1",
                    "project_id": "some-project",
                },
                "type": "k8s_cluster",
            },
            "timestamp": "2024-02-13 13:07:29.505948000",
        },
    ),
    PantherRuleTest(
        Name="Error Creating Pod",
        ExpectedResult=False,
        Log={
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "john.doe@company.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "io.k8s.core.v1.pods.create",
                        "resource": "core/v1/namespaces/default/pods/test-privileged-pod",
                    }
                ],
                "methodName": "io.k8s.core.v1.pods.create",
                "request": {
                    "@type": "core.k8s.io/v1.Pod",
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "test-privileged-pod", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {
                                "image": "nginx",
                                "imagePullPolicy": "Always",
                                "name": "nginx",
                                "resources": {},
                                "securityContext": {"runAsNonRoot": False},
                            }
                        ]
                    },
                    "status": {},
                },
                "requestMetadata": {"callerIP": "1.2.3.4"},
                "resourceName": "core/v1/namespaces/default/pods/test-privileged-pod",
                "response": {
                    "@type": "core.k8s.io/v1.Status",
                    "apiVersion": "v1",
                    "code": 409,
                    "details": {"kind": "pods", "name": "test-privileged-pod"},
                    "kind": "Status",
                    "message": 'pods "test-privileged-pod" already exists',
                    "metadata": {},
                    "reason": "AlreadyExists",
                    "status": "Failure",
                },
                "serviceName": "k8s.io",
                "status": {"code": 10, "message": 'pods "test-privileged-pod" already exists'},
            },
            "receiveTimestamp": "2024-02-13 13:13:33.486605432",
            "resource": {
                "labels": {
                    "cluster_name": "some-project-cluster",
                    "location": "us-west1",
                    "project_id": "some-project",
                },
                "type": "k8s_cluster",
            },
            "timestamp": "2024-02-13 13:13:24.079140000",
        },
    ),
]


class GCPK8SPrivilegedPodCreated(PantherRule):
    RuleID = "GCP.K8S.Privileged.Pod.Created-prototype"
    DisplayName = "GCP K8S Privileged Pod Created"
    LogTypes = [LogType.GCP_AuditLog]
    Severity = PantherSeverity.High
    Description = "Alerts when a user creates privileged pod. These particular pods have full access to the host’s namespace and devices, have the ability to exploit the kernel, have dangerous linux capabilities, and can be a powerful launching point for further attacks. In the event of a successful container escape where a user is operating with root privileges, the attacker retains this role on the node.\n"
    Runbook = "Investigate the reason of creating privileged pod. Advise that it is discouraged practice. Create ticket if appropriate.\n"
    Reference = "https://www.golinuxcloud.com/kubernetes-privileged-pod-examples/"
    Reports = {"MITRE ATT&CK": ["TA0004:T1548"]}
    Tests = gcpk8_s_privileged_pod_created_tests

    def rule(self, event):
        if deep_get(event, "protoPayload", "response", "status") == "Failure":
            return False
        if deep_get(event, "protoPayload", "methodName") != "io.k8s.core.v1.pods.create":
            return False
        authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        containers_info = deep_walk(event, "protoPayload", "response", "spec", "containers")
        for auth in authorization_info:
            if (
                auth.get("permission") == "io.k8s.core.v1.pods.create"
                and auth.get("granted") is True
            ):
                for security_context in containers_info:
                    if (
                        deep_get(security_context, "securityContext", "privileged") is True
                        or deep_get(security_context, "securityContext", "runAsNonRoot") is False
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
        pod_name = deep_get(event, "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
        project_id = deep_get(
            event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>"
        )
        return f"[GCP]: [{actor}] created a privileged pod [{pod_name}] in project [{project_id}]"

    def alert_context(self, event):
        context = gcp_alert_context(event)
        containers_info = deep_walk(event, "protoPayload", "response", "spec", "containers")
        context["pod_security_context"] = [i.get("securityContext") for i in containers_info]
        return context
