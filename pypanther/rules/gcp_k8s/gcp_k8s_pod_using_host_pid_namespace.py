from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPK8sPodUsingHostPIDNamespace(Rule):
    id = "GCP.K8s.Pod.Using.Host.PID.Namespace-prototype"
    display_name = "GCP K8s Pod Using Host PID Namespace"
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["GCP", "Optional"]
    default_severity = Severity.MEDIUM
    default_description = "This detection monitors for any pod creation or modification using the host PID namespace. The Host PID namespace enables a pod and its containers to have direct access and share the same view as of the host’s processes. This can offer a powerful escape hatch to the underlying host."
    default_runbook = "Investigate a reason of creating a pod using the host PID namespace. Advise that it is discouraged practice. Create ticket if appropriate."
    reports = {"MITRE ATT&CK": ["TA0004:T1611", "TA0002:T1610"]}
    default_reference = "https://medium.com/snowflake/from-logs-to-detection-using-snowflake-and-panther-to-detect-k8s-threats-d72f70a504d7"
    METHODS_TO_CHECK = ["io.k8s.core.v1.pods.create", "io.k8s.core.v1.pods.update", "io.k8s.core.v1.pods.patch"]

    def rule(self, event):
        method = event.deep_get("protoPayload", "methodName")
        request_host_pid = event.deep_get("protoPayload", "request", "spec", "hostPID")
        response_host_pid = event.deep_get("protoPayload", "responce", "spec", "hostPID")
        if (request_host_pid is True or response_host_pid is True) and method in self.METHODS_TO_CHECK:
            return True
        return False

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: [{actor}] created or modified pod using the host PID namespace in project [{project_id}]"

    def alert_context(self, event):
        return gcp_alert_context(event)

    tests = [
        RuleTest(
            name="triggers",
            expected_result=True,
            log={
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "io.k8s.core.v1.pods.create",
                        "resource": "core/v1/namespaces/default/pods/nginx-test",
                    },
                ],
                "protoPayload": {"methodName": "io.k8s.core.v1.pods.create", "request": {"spec": {"hostPID": True}}},
            },
        ),
        RuleTest(
            name="ignore",
            expected_result=False,
            log={
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "io.k8s.core.v1.pods.create",
                        "resource": "core/v1/namespaces/default/pods/nginx-test",
                    },
                ],
                "protoPayload": {"methodName": "io.k8s.core.v1.pods.create", "request": {"spec": {"hostPID": False}}},
            },
        ),
    ]
