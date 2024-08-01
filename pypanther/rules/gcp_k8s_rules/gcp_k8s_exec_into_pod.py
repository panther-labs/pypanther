from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp_base_helpers import get_k8s_info
from pypanther.helpers.gcp_environment import PRODUCTION_PROJECT_IDS, rule_exceptions
from pypanther.helpers.panther_base_helpers import deep_walk

gcpk8s_exec_into_pod_tests: list[RuleTest] = [
    RuleTest(
        name="Allowed User",
        expected_result=False,
        log={
            "protoPayload": {
                "authenticationInfo": {
                    "principalEmail": "system:serviceaccount:example-namespace:example-namespace-service-account",
                },
                "authorizationInfo": [
                    {
                        "permission": "io.k8s.core.v1.pods.exec.create",
                        "resource": "core/v1/namespaces/opa/pods/opa-57998cf7c5-bjkfk/exec",
                    },
                ],
                "methodName": "io.k8s.core.v1.pods.exec.create",
                "requestMetadata": {
                    "callerIp": "88.88.88.88",
                    "callerSuppliedUserAgent": "kubectl/v1.40.8 (darwin/amd64) kubernetes/6575935",
                },
                "resourceName": "core/v1/namespaces/example/pods/one-off-46666967280/exec",
                "timestamp": "2022-03-04T16:01:49.978756Z",
            },
            "resource": {"type": "k8s_cluster", "labels": {"project_id": "rigup-production"}},
        },
    ),
    RuleTest(
        name="Disallowed User",
        expected_result=True,
        log={
            "protoPayload": {
                "authenticationInfo": {"principalEmail": "disallowed.user@example.com"},
                "authorizationInfo": [
                    {
                        "permission": "io.k8s.core.v1.pods.exec.create",
                        "resource": "core/v1/namespaces/example/pods/example-57998cf7c5-bjkfk/exec",
                    },
                ],
                "methodName": "io.k8s.core.v1.pods.exec.create",
                "requestMetadata": {
                    "callerIp": "88.88.88.88",
                    "callerSuppliedUserAgent": "kubectl/v1.40.8 (darwin/amd64) kubernetes/6575935",
                },
                "resourceName": "core/v1/namespaces/example/pods/one-off-valerii-tovstyk-1646666967280/exec",
                "timestamp": "2022-03-04T16:01:49.978756Z",
            },
            "resource": {"type": "k8s_cluster", "labels": {"project_id": "rigup-production"}},
        },
    ),
    RuleTest(
        name="Disallowed User2 - not an allowed namespace",
        expected_result=True,
        log={
            "protoPayload": {
                "authenticationInfo": {"principalEmail": "example-allowed-user@example.com"},
                "authorizationInfo": [
                    {
                        "permission": "io.k8s.core.v1.pods.exec.create",
                        "resource": "core/v1/namespaces/istio-system/pods/opa-57998cf7c5-bjkfk/exec",
                    },
                ],
                "methodName": "io.k8s.core.v1.pods.exec.create",
                "requestMetadata": {
                    "callerIp": "88.88.88.88",
                    "callerSuppliedUserAgent": "kubectl/v1.40.8 (darwin/amd64) kubernetes/6575935",
                },
                "resourceName": "core/v1/namespaces/istio-system/pods/one-off-valerii-tovstyk-1646666967280/exec",
                "timestamp": "2022-03-04T16:01:49.978756Z",
            },
            "resource": {"type": "k8s_cluster", "labels": {"project_id": "rigup-production"}},
        },
    ),
]


@panther_managed
class GCPK8sExecIntoPod(Rule):
    id = "GCP.K8s.ExecIntoPod-prototype"
    display_name = "Exec into Pod"
    enabled = False
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["GCP", "Security Control", "Configuration Required"]
    default_severity = Severity.MEDIUM
    default_description = "Alerts when users exec into pod. Possible to specify specific projects and allowed users.\n"
    default_runbook = "Investigate the user and determine why. Advise that it is discouraged practice. Create ticket if appropriate.\n"
    default_reference = "https://cloud.google.com/migrate/containers/docs/troubleshooting/executing-shell-commands"
    tests = gcpk8s_exec_into_pod_tests

    def rule(self, event):
        # Defaults to False (no alert) unless method is exec and principal not allowed
        if not all(
            [
                deep_walk(event, "protoPayload", "methodName") == "io.k8s.core.v1.pods.exec.create",
                deep_walk(event, "resource", "type") == "k8s_cluster",
            ],
        ):
            return False
        k8s_info = get_k8s_info(event)
        principal = deep_walk(k8s_info, "principal", default="<NO PRINCIPAL>")
        namespace = deep_walk(k8s_info, "namespace", default="<NO NAMESPACE>")
        project_id = deep_walk(k8s_info, "project_id", default="<NO PROJECT_ID>")
        # rule_exceptions that are allowed temporarily are defined in gcp_environment.py
        # Some execs have principal which is long numerical UUID, appears to be k8s internals
        for allowed_principal in deep_walk(rule_exceptions, "gcp_k8s_exec_into_pod", "allowed_principals", default=[]):
            allowed_principals = deep_walk(allowed_principal, "principals", default=[])
            allowed_namespaces = deep_walk(allowed_principal, "namespaces", default=[])
            allowed_project_ids = deep_walk(allowed_principal, "projects", default=[])
            if (
                principal in allowed_principals
                and (namespace in allowed_namespaces or allowed_namespaces == [])
                and (project_id in allowed_project_ids or allowed_project_ids == [])
            ):
                if "@" not in principal:
                    return False
        return True

    def severity(self, event):
        project_id = deep_walk(get_k8s_info(event), "project_id", default="<NO PROJECT_ID>")
        if project_id in PRODUCTION_PROJECT_IDS:
            return "high"
        return "info"

    def title(self, event):
        # TODO: use unified data model field in title for actor
        k8s_info = get_k8s_info(event)
        principal = deep_walk(k8s_info, "principal", default="<NO PRINCIPAL>")
        project_id = deep_walk(k8s_info, "project_id", default="")
        pod = deep_walk(k8s_info, "pod", default="")
        namespace = deep_walk(k8s_info, "namespace", default="")
        return f"Exec into pod namespace/{namespace}/pod/{pod} by {principal} in {project_id}"

    def alert_context(self, event):
        return get_k8s_info(event)
