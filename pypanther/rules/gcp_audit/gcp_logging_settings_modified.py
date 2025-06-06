from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GCPLoggingSettingsModified(Rule):
    default_description = "Detects any changes made to logging settings"
    display_name = "GCP Logging Settings Modified"
    default_reference = "https://cloud.google.com/logging/docs/default-settings"
    default_severity = Severity.LOW
    log_types = [LogType.GCP_AUDIT_LOG]
    id = "GCP.Logging.Settings.Modified-prototype"

    def rule(self, event):
        return all(
            [
                event.deep_get("protoPayload", "serviceName", default="") == "logging.googleapis.com",
                "Update" in event.deep_get("protoPayload", "methodName", default=""),
            ],
        )

    def title(self, event):
        resource = event.deep_get("protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        return f"GCP [{resource}] logging settings modified by [{actor}]."

    def alert_context(self, event):
        return {
            "resource": event.deep_get("protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>"),
            "actor": event.deep_get(
                "protoPayload",
                "authenticationInfo",
                "principalEmail",
                default="<ACTOR_NOT_FOUND>",
            ),
            "method": event.deep_get("protoPayload", "methodName", default="<METHOD_NOT_FOUND>"),
        }

    tests = [
        RuleTest(
            name="Other Event",
            expected_result=False,
            log={
                "insertid": "abcdefghijklmn",
                "logname": "projects/gcp-project1/logs/cloudaudit.googleapis.com%2Factivity",
                "operation": {
                    "id": "1234567890123-gcp-project1:abcdefghijklmnopqrstuvwz",
                    "last": True,
                    "producer": "bigquery.googleapis.com",
                },
                "p_any_emails": ["user@company.io"],
                "p_any_ip_addresses": ["1.2.3.4"],
                "p_event_time": "2023-03-28 18:37:06.079",
                "p_log_type": "GCP.AuditLog",
                "p_parse_time": "2023-03-28 18:38:14.478",
                "p_row_id": "06bf03d9d5dfbadba981899e1787bf05",
                "p_schema_version": 0,
                "p_source_id": "964c7894-9a0d-4ddf-864f-0193438221d6",
                "p_source_label": "gcp-logsource",
                "protopayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user@company.io"},
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "bigquery.tables.delete",
                            "resource": "projects/gcp-project1/datasets/test1/tables/newtable",
                        },
                    ],
                    "metadata": {
                        "@type": "type.googleapis.com/google.cloud.audit.BigQueryAuditMetadata",
                        "methodName": "google.cloud.bigquery.v2.JobService.InsertJob",
                        "requestMetadata": {
                            "callerIP": "1.2.3.4",
                            "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)",
                        },
                        "resourceName": "projects/gcp-project1/datasets/test1/tables/newtable",
                        "serviceName": "bigquery.googleapis.com",
                        "status": {},
                        "tableDeletion": {
                            "jobName": "projects/gcp-project1/jobs/bquxjob_5e4a0679_18729a639d7",
                            "reason": "QUERY",
                        },
                    },
                    "receivetimestamp": "2023-03-28 18:37:06.745",
                    "resource": {
                        "labels": {"dataset_id": "test1", "project_id": "gcp-project1"},
                        "type": "bigquery_dataset",
                    },
                    "severity": "NOTICE",
                    "timestamp": "2023-03-28 18:37:06.079",
                },
            },
        ),
        RuleTest(
            name="Sink Update Event",
            expected_result=True,
            log={
                "insertid": "ezyd47c12y",
                "logname": "projects/gcp-project1/logs/cloudaudit.googleapis.com%2Factivity",
                "p_any_ip_addresses": ["1.2.3.4"],
                "p_event_time": "2023-03-09 16:41:30.524",
                "p_log_type": "GCP.AuditLog",
                "p_parse_time": "2023-03-09 16:44:14.617",
                "p_row_id": "1234567909689348911",
                "p_source_id": "4fc88a5a-2d51-4279-9c4a-08fa7cc52566",
                "p_source_label": "gcplogsource",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "test@company.io"},
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "logging.sinks.update",
                            "resource": "projects/gcp-project1/sinks/log-sink",
                            "resourceAttributes": {
                                "name": "projects/gcp-project1/sinks/log-sink",
                                "service": "logging.googleapis.com",
                            },
                        },
                    ],
                    "methodName": "google.logging.v2.ConfigServiceV2.UpdateSink",
                    "request": {
                        "@type": "type.googleapis.com/google.logging.v2.UpdateSinkRequest",
                        "sink": {
                            "destination": "pubsub.googleapis.com/projects/gcp-project1/topics/gcp-topic1",
                            "exclusions": [{"filter": "protoPayload.serviceName = 'k8s.io", "name": "excludek8s"}],
                            "name": "log-sink",
                            "writerIdentity": "serviceAccount:p197946410614-915152@gcp-sa-logging.iam.gserviceaccount.com",
                        },
                        "sinkName": "projects/gcp-project1/sinks/log-sink",
                        "uniqueWriterIdentity": True,
                        "updateMask": "exclusions",
                    },
                    "requestMetadata": {
                        "callerIP": "1.2.3.4",
                        "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2023-03-09T16:41:30.540045105Z"},
                    },
                    "resourceName": "projects/gcp-project1/sinks/log-sink",
                    "serviceName": "logging.googleapis.com",
                    "status": {},
                },
                "receivetimestamp": "2023-03-09 16:41:32.21",
                "resource": {
                    "labels": {"destination": "", "name": "log-sink", "project_id": "gcp-project1"},
                    "type": "logging_sink",
                },
                "severity": "NOTICE",
                "timestamp": "2023-03-09 16:41:30.524",
            },
        ),
    ]
