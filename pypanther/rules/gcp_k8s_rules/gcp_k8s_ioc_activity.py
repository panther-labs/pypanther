from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get

gcpk8s_ioc_activity_tests: list[RuleTest] = [
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


@panther_managed
class GCPK8sIOCActivity(Rule):
    id = "GCP.K8s.IOC.Activity-prototype"
    display_name = "GCP K8s IOCActivity"
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["GCP", "Optional"]
    default_severity = Severity.MEDIUM
    default_description = (
        "This detection monitors for any kubernetes API Request originating from an Indicator of Compromise."
    )
    reports = {"MITRE ATT&CK": ["T1573.002"]}
    default_runbook = "Add IP address the request is originated from to banned addresses."
    default_reference = "https://medium.com/snowflake/from-logs-to-detection-using-snowflake-and-panther-to-detect-k8s-threats-d72f70a504d7"
    tests = gcpk8s_ioc_activity_tests

    def rule(self, event):
        if deep_get(event, "operation", "producer") == "k8s.io" and deep_get(event, "p_enrichment", "tor_exit_nodes"):
            return True
        return False

    def title(self, event):
        actor = deep_get(event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        operation = deep_get(event, "protoPayload", "methodName", default="<OPERATION_NOT_FOUND>")
        project_id = deep_get(event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: [{actor}] performed [{operation}] on project [{project_id}]"

    def alert_context(self, event):
        context = gcp_alert_context(event)
        context["tor_exit_nodes"] = deep_get(event, "p_enrichment", "tor_exit_nodes")
        return context
