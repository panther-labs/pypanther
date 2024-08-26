from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

gcpsql_config_changes_tests: list[RuleTest] = [
    RuleTest(
        name="Sql Instance Change",
        expected_result=True,
        log={
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
    ),
]


@panther_managed
class GCPSQLConfigChanges(Rule):
    id = "GCP.SQL.ConfigChanges-prototype"
    display_name = "GCP SQL Config Changes"
    dedup_period_minutes = 720
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["GCP", "Database"]
    reports = {"CIS": ["2.11"]}
    default_severity = Severity.LOW
    default_description = "Monitoring changes to Sql Instance configuration may reduce time to detect and correct misconfigurations done on sql server.\n"
    default_runbook = "Validate the Sql Instance configuration change was safe"
    default_reference = "https://cloud.google.com/sql/docs/mysql/instance-settings"
    summary_attributes = ["severity", "p_any_ip_addresses", "p_any_domain_names"]
    tests = gcpsql_config_changes_tests

    def rule(self, event):
        return deep_get(event, "protoPayload", "methodName") == "cloudsql.instances.update"

    def dedup(self, event):
        return deep_get(event, "resource", "labels", "project_id", default="<UNKNOWN_PROJECT>")
