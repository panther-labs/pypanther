from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPK8sIOCActivity(Rule):
    id = "GCP.K8s.IOC.Activity-prototype"
    display_name = "GCP K8s IOCActivity"
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["GCP", "Optional", "Encrypted Channel - Asymmetric Cryptography", "Command and Control"]
    default_severity = Severity.MEDIUM
    default_description = (
        "This detection monitors for any kubernetes API Request originating from an Indicator of Compromise."
    )
    reports = {"MITRE ATT&CK": ["TA0011:T1573.002"]}
    default_runbook = "Add IP address the request is originated from to banned addresses."
    default_reference = "https://medium.com/snowflake/from-logs-to-detection-using-snowflake-and-panther-to-detect-k8s-threats-d72f70a504d7"

    def rule(self, event):
        if event.deep_get("operation", "producer") == "k8s.io" and event.deep_get("p_enrichment", "tor_exit_nodes"):
            return True
        return False

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        operation = event.deep_get("protoPayload", "methodName", default="<OPERATION_NOT_FOUND>")
        project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: [{actor}] performed [{operation}] on project [{project_id}]"

    def alert_context(self, event):
        context = gcp_alert_context(event)
        context["tor_exit_nodes"] = event.deep_get("p_enrichment", "tor_exit_nodes")
        return context

    tests = [
        RuleTest(
            name="triggers",
            expected_result=True,
            log={"operation": {"producer": "k8s.io"}, "p_enrichment": {"tor_exit_nodes": ["1.1.1.1"]}},
        ),
        RuleTest(
            name="ignore",
            expected_result=False,
            log={"operation": {"producer": "chrome"}, "p_enrichment": {"tor_exit_nodes": ["1.1.1.1"]}},
        ),
    ]
