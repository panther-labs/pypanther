from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GCPBigQueryLargeScan(Rule):
    default_description = "Detect any BigQuery query that is doing a very large scan (> 1 GB)."
    display_name = "GCP BigQuery Large Scan"
    default_reference = "https://cloud.google.com/bigquery/docs/running-queries"
    default_severity = Severity.INFO
    log_types = [LogType.GCP_AUDIT_LOG]
    id = "GCP.BigQuery.Large.Scan-prototype"
    # 1.07 GB
    QUERY_THRESHOLD_BYTES = 1073741824

    def rule(self, event):
        return all(
            [
                event.deep_get("resource", "type", default="<type not found>").startswith("bigquery"),
                event.deep_get("operation", "last") is True,
                event.deep_get("protoPayload", "metadata", "jobChange", "job", "jobConfig", "type") == "QUERY",
                event.deep_get(
                    "protoPayload",
                    "metadata",
                    "jobChange",
                    "job",
                    "jobConfig",
                    "queryConfig",
                    "statementType",
                )
                == "SELECT",
                int(
                    event.deep_get(
                        "protoPayload",
                        "metadata",
                        "jobChange",
                        "job",
                        "jobStats",
                        "queryStats",
                        "totalBilledBytes",
                        default=0,
                    ),
                )
                > self.QUERY_THRESHOLD_BYTES,
            ],
        )

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        query_size = event.deep_get(
            "protoPayload",
            "metadata",
            "jobChange",
            "job",
            "jobStats",
            "queryStats",
            "totalBilledBytes",
            default=0,
        )
        return f"GCP: [{actor}] ran a large BigQuery query of [{query_size}] bytes."

    def alert_context(self, event):
        return {
            "query": event.deep_get(
                "protoPayload",
                "metadata",
                "jobChange",
                "job",
                "jobConfig",
                "queryConfig",
                "query",
                default="<QUERY_NOT_FOUND>",
            ),
            "actor": event.deep_get(
                "protoPayload",
                "authenticationInfo",
                "principalEmail",
                default="<ACTOR_NOT_FOUND>",
            ),
            "query_size": event.deep_get(
                "protoPayload",
                "metadata",
                "jobChange",
                "job",
                "jobStats",
                "queryStats",
                "totalBilledBytes",
                default=0,
            ),
        }

    tests = [
        RuleTest(
            name="small query",
            expected_result=False,
            log={
                "insertid": "ABCDEFGHIJKL",
                "logname": "projects/gcp-project1/logs/cloudaudit.googleapis.com%2Fdata_access",
                "operation": {
                    "id": "0123456789012-gcp-project1:abcdefg_hijklmnop_1234567abcd",
                    "last": True,
                    "producer": "bigquery.googleapis.com",
                },
                "p_any_emails": ["user@company.io"],
                "p_any_ip_addresses": ["1.2.3.4"],
                "p_event_time": "2023-03-28 17:37:02.096",
                "p_log_type": "GCP.AuditLog",
                "p_parse_time": "2023-03-28 17:38:14.621",
                "p_row_id": "de00d3dcdaeee4b4d5f7fa9d17b4c203",
                "p_schema_version": 0,
                "p_source_id": "964c7894-9a0d-4ddf-864f-0193438221d6",
                "p_source_label": "gcp-logsource",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user@company.io"},
                    "authorizationInfo": [
                        {"granted": True, "permission": "bigquery.jobs.create", "resource": "projects/gcp-project1"},
                    ],
                    "metadata": {
                        "@type": "type.googleapis.com/google.cloud.audit.BigQueryAuditMetadata",
                        "jobChange": {
                            "after": "DONE",
                            "job": {
                                "jobConfig": {
                                    "queryConfig": {
                                        "createDisposition": "CREATE_IF_NEEDED",
                                        "destinationTable": "projects/gcp-project1/datasets/_c2b49f742788f188022fcec1f1622e7404b40ce5/tables/anondea8e77183dcdf1cf93a47b5003036409a525808207450ab80db17fcc8cdcf53",
                                        "priority": "QUERY_INTERACTIVE",
                                        "query": "-- This query shows a list of the daily top Google Search terms.\nSELECT\n   *\nFROM `bigquery-public-data.google_trends.top_terms`",
                                        "statementType": "SELECT",
                                        "writeDisposition": "WRITE_TRUNCATE",
                                    },
                                    "type": "QUERY",
                                },
                                "jobName": "projects/gcp-project1/jobs/abcdefg_hijklmnop_1234567abcd",
                                "jobStats": {
                                    "createTime": "2023-03-28T17:36:49.087Z",
                                    "endTime": "2023-03-28T17:37:02.092Z",
                                    "queryStats": {
                                        "billingTier": 1,
                                        "outputRowCount": "43683701",
                                        "referencedTables": [
                                            "projects/bigquery-public-data/datasets/google_trends/tables/top_terms",
                                        ],
                                        "totalBilledBytes": "100000",
                                        "totalProcessedBytes": "100000",
                                    },
                                    "startTime": "2023-03-28T17:36:49.224Z",
                                    "totalSlotMs": "259581",
                                },
                                "jobStatus": {"jobState": "DONE"},
                            },
                        },
                    },
                    "methodName": "google.cloud.bigquery.v2.JobService.InsertJob",
                    "requestMetadata": {
                        "callerIP": "1.2.3.4",
                        "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)",
                    },
                    "resourceName": "projects/gcp-project1/jobs/abcdefg_hijklmnop_1234567abcd",
                    "serviceName": "bigquery.googleapis.com",
                    "status": {},
                },
                "receivetimestamp": "2023-03-28 17:37:02.114",
                "resource": {"labels": {"location": "US", "project_id": "gcp-project1"}, "type": "bigquery_project"},
                "severity": "INFO",
                "timestamp": "2023-03-28 17:37:02.096",
            },
        ),
        RuleTest(
            name="Large Query",
            expected_result=True,
            log={
                "insertid": "ABCDEFGHIJKL",
                "logname": "projects/gcp-project1/logs/cloudaudit.googleapis.com%2Fdata_access",
                "operation": {
                    "id": "0123456789012-gcp-project1:abcdefg_hijklmnop_1234567abcd",
                    "last": True,
                    "producer": "bigquery.googleapis.com",
                },
                "p_any_emails": ["user@company.io"],
                "p_any_ip_addresses": ["1.2.3.4"],
                "p_event_time": "2023-03-28 17:37:02.096",
                "p_log_type": "GCP.AuditLog",
                "p_parse_time": "2023-03-28 17:38:14.621",
                "p_row_id": "de00d3dcdaeee4b4d5f7fa9d17b4c203",
                "p_schema_version": 0,
                "p_source_id": "964c7894-9a0d-4ddf-864f-0193438221d6",
                "p_source_label": "gcp-logsource",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user@company.io"},
                    "authorizationInfo": [
                        {"granted": True, "permission": "bigquery.jobs.create", "resource": "projects/gcp-project1"},
                    ],
                    "metadata": {
                        "@type": "type.googleapis.com/google.cloud.audit.BigQueryAuditMetadata",
                        "jobChange": {
                            "after": "DONE",
                            "job": {
                                "jobConfig": {
                                    "queryConfig": {
                                        "createDisposition": "CREATE_IF_NEEDED",
                                        "destinationTable": "projects/gcp-project1/datasets/_c2b49f742788f188022fcec1f1622e7404b40ce5/tables/anondea8e77183dcdf1cf93a47b5003036409a525808207450ab80db17fcc8cdcf53",
                                        "priority": "QUERY_INTERACTIVE",
                                        "query": "-- This query shows a list of the daily top Google Search terms.\nSELECT\n   *\nFROM `bigquery-public-data.google_trends.top_terms`",
                                        "statementType": "SELECT",
                                        "writeDisposition": "WRITE_TRUNCATE",
                                    },
                                    "type": "QUERY",
                                },
                                "jobName": "projects/gcp-project1/jobs/abcdefg_hijklmnop_1234567abcd",
                                "jobStats": {
                                    "createTime": "2023-03-28T17:36:49.087Z",
                                    "endTime": "2023-03-28T17:37:02.092Z",
                                    "queryStats": {
                                        "billingTier": 1,
                                        "outputRowCount": "43683701",
                                        "referencedTables": [
                                            "projects/bigquery-public-data/datasets/google_trends/tables/top_terms",
                                        ],
                                        "totalBilledBytes": "3097493504",
                                        "totalProcessedBytes": "3096864198",
                                    },
                                    "startTime": "2023-03-28T17:36:49.224Z",
                                    "totalSlotMs": "259581",
                                },
                                "jobStatus": {"jobState": "DONE"},
                            },
                        },
                    },
                    "methodName": "google.cloud.bigquery.v2.JobService.InsertJob",
                    "requestMetadata": {
                        "callerIP": "1.2.3.4",
                        "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)",
                    },
                    "resourceName": "projects/gcp-project1/jobs/abcdefg_hijklmnop_1234567abcd",
                    "serviceName": "bigquery.googleapis.com",
                    "status": {},
                },
                "receivetimestamp": "2023-03-28 17:37:02.114",
                "resource": {"labels": {"location": "US", "project_id": "gcp-project1"}, "type": "bigquery_project"},
                "severity": "INFO",
                "timestamp": "2023-03-28 17:37:02.096",
            },
        ),
    ]
