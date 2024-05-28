from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

gcpsql_config_changes_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Sql Instance Change",
        ExpectedResult=True,
        Log={
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "status": {},
                "authenticationInfo": {"principalEmail": "user@runpanther.io"},
                "requestMetadata": {
                    "callerIp": "136.24.229.58",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36,gzip(gfe)",
                    "requestAttributes": {"time": "2020-05-15T04:28:42.243082428Z", "auth": {}},
                    "destinationAttributes": {},
                },
                "serviceName": "storage.googleapis.com",
                "methodName": "cloudsql.instances.update",
            },
            "resource": {
                "type": "sql_instance",
                "labels": {"project_id": "western-verve-123456", "location": "asia-northeast2"},
            },
        },
    )
]


class GCPSQLConfigChanges(PantherRule):
    RuleID = "GCP.SQL.ConfigChanges-prototype"
    DisplayName = "GCP SQL Config Changes"
    DedupPeriodMinutes = 720
    LogTypes = [LogType.GCP_AuditLog]
    Tags = ["GCP", "Database"]
    Reports = {"CIS": ["2.11"]}
    Severity = PantherSeverity.Low
    Description = "Monitoring changes to Sql Instance configuration may reduce time to detect and correct misconfigurations done on sql server.\n"
    Runbook = "Validate the Sql Instance configuration change was safe"
    Reference = "https://cloud.google.com/sql/docs/mysql/instance-settings"
    SummaryAttributes = ["severity", "p_any_ip_addresses", "p_any_domain_names"]
    Tests = gcpsql_config_changes_tests

    def rule(self, event):
        return deep_get(event, "protoPayload", "methodName") == "cloudsql.instances.update"

    def dedup(self, event):
        return deep_get(event, "resource", "labels", "project_id", default="<UNKNOWN_PROJECT>")
