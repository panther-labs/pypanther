from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


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

    def rule(self, event):
        return event.deep_get("protoPayload", "methodName") == "cloudsql.instances.update"

    def dedup(self, event):
        return event.deep_get("resource", "labels", "project_id", default="<UNKNOWN_PROJECT>")

    tests = [
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
