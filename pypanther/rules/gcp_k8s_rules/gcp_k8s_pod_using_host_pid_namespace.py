from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

gcpk8s_pod_using_host_pid_namespace_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="triggers",
        ExpectedResult=True,
        Log={
            "authorizationInfo": [
                {
                    "granted": True,
                    "permission": "io.k8s.core.v1.pods.create",
                    "resource": "core/v1/namespaces/default/pods/nginx-test",
                }
            ],
            "protoPayload": {
                "methodName": "io.k8s.core.v1.pods.create",
                "request": {"spec": {"hostPID": True}},
            },
        },
    ),
    PantherRuleTest(
        Name="ignore",
        ExpectedResult=False,
        Log={
            "authorizationInfo": [
                {
                    "granted": True,
                    "permission": "io.k8s.core.v1.pods.create",
                    "resource": "core/v1/namespaces/default/pods/nginx-test",
                }
            ],
            "protoPayload": {
                "methodName": "io.k8s.core.v1.pods.create",
                "request": {"spec": {"hostPID": False}},
            },
        },
    ),
]


class GCPK8sPodUsingHostPIDNamespace(PantherRule):
    RuleID = "GCP.K8s.Pod.Using.Host.PID.Namespace-prototype"
    DisplayName = "GCP K8s Pod Using Host PID Namespace"
    LogTypes = [LogType.GCP_AuditLog]
    Tags = ["GCP", "Optional"]
    Severity = PantherSeverity.Medium
    Description = "This detection monitors for any pod creation or modification using the host PID namespace. The Host PID namespace enables a pod and its containers to have direct access and share the same view as of the host’s processes. This can offer a powerful escape hatch to the underlying host."
    Runbook = "Investigate a reason of creating a pod using the host PID namespace. Advise that it is discouraged practice. Create ticket if appropriate."
    Reports = {"MITRE ATT&CK": ["TA0004:T1611", "TA0002:T1610"]}
    Reference = "https://medium.com/snowflake/from-logs-to-detection-using-snowflake-and-panther-to-detect-k8s-threats-d72f70a504d7"
    Tests = gcpk8s_pod_using_host_pid_namespace_tests
    METHODS_TO_CHECK = [
        "io.k8s.core.v1.pods.create",
        "io.k8s.core.v1.pods.update",
        "io.k8s.core.v1.pods.patch",
    ]

    def rule(self, event):
        method = deep_get(event, "protoPayload", "methodName")
        request_host_pid = deep_get(event, "protoPayload", "request", "spec", "hostPID")
        response_host_pid = deep_get(event, "protoPayload", "responce", "spec", "hostPID")
        if (
            request_host_pid is True or response_host_pid is True
        ) and method in self.METHODS_TO_CHECK:
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
        project_id = deep_get(
            event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>"
        )
        return f"[GCP]: [{actor}] created or modified pod using the host PID namespace in project [{project_id}]"

    def alert_context(self, event):
        return gcp_alert_context(event)
