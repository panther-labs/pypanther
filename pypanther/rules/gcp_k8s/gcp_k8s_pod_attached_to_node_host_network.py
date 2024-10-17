from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPK8sPodAttachedToNodeHostNetwork(Rule):
    id = "GCP.K8s.Pod.Attached.To.Node.Host.Network-prototype"
    display_name = "GCP K8s Pod Attached To Node Host Network"
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["GCP", "Optional"]
    default_severity = Severity.MEDIUM
    default_description = "This detection monitor for the creation of pods which are attached to the host's network. This allows a pod to listen to all network traffic for all deployed computer on that particular node and communicate with other compute on the network namespace. Attackers can use this to capture secrets passed in arguments or connections."
    reports = {"MITRE ATT&CK": ["TA0004:T1611"]}
    default_runbook = "Investigate a reason of creating a pod which is attached to the host's network. Advise that it is discouraged practice. Create ticket if appropriate."
    default_reference = "https://medium.com/snowflake/from-logs-to-detection-using-snowflake-and-panther-to-detect-k8s-threats-d72f70a504d7"

    def rule(self, event):
        if event.deep_get("protoPayload", "methodName") not in (
            "io.k8s.core.v1.pods.create",
            "io.k8s.core.v1.pods.update",
            "io.k8s.core.v1.pods.patch",
        ):
            return False
        host_network = event.deep_walk("protoPayload", "request", "spec", "hostNetwork")
        if host_network is not True:
            return False
        return True

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: [{actor}] created or modified pod which is attached to the host's network in project [{project_id}]"

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
                "protoPayload": {
                    "methodName": "io.k8s.core.v1.pods.create",
                    "request": {"spec": {"hostNetwork": True}},
                },
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
                "protoPayload": {
                    "methodName": "io.k8s.core.v1.pods.create",
                    "request": {"spec": {"hostNetwork": False}},
                },
            },
        ),
    ]
