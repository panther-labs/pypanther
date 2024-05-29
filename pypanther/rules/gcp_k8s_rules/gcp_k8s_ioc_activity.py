from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

gcpk8s_ioc_activity_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="triggers",
        ExpectedResult=True,
        Log={"operation": {"producer": "k8s.io"}, "p_enrichment": {"tor_exit_nodes": ["1.1.1.1"]}},
    ),
    PantherRuleTest(
        Name="ignore",
        ExpectedResult=False,
        Log={"operation": {"producer": "chrome"}, "p_enrichment": {"tor_exit_nodes": ["1.1.1.1"]}},
    ),
]


class GCPK8sIOCActivity(PantherRule):
    RuleID = "GCP.K8s.IOC.Activity-prototype"
    DisplayName = "GCP K8s IOCActivity"
    LogTypes = [LogType.GCP_AuditLog]
    Tags = ["GCP", "Optional"]
    Severity = PantherSeverity.Medium
    Description = "This detection monitors for any kubernetes API Request originating from an Indicator of Compromise."
    Reports = {"MITRE ATT&CK": ["T1573.002"]}
    Runbook = "Add IP address the request is originated from to banned addresses."
    Reference = "https://medium.com/snowflake/from-logs-to-detection-using-snowflake-and-panther-to-detect-k8s-threats-d72f70a504d7"
    Tests = gcpk8s_ioc_activity_tests

    def rule(self, event):
        if deep_get(event, "operation", "producer") == "k8s.io" and deep_get(
            event, "p_enrichment", "tor_exit_nodes"
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
        operation = deep_get(event, "protoPayload", "methodName", default="<OPERATION_NOT_FOUND>")
        project_id = deep_get(
            event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>"
        )
        return f"[GCP]: [{actor}] performed [{operation}] on project [{project_id}]"

    def alert_context(self, event):
        context = gcp_alert_context(event)
        context["tor_exit_nodes"] = deep_get(event, "p_enrichment", "tor_exit_nodes")
        return context
