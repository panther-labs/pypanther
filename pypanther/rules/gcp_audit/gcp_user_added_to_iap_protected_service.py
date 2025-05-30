from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GCPUserAddedtoIAPProtectedService(Rule):
    default_description = "A user has been granted access to a IAP protected service."
    display_name = "GCP User Added to IAP Protected Service"
    default_runbook = "Note: GCP logs all bindings everytime this event occurs, not just changes. Bindings should be reviewed to ensure no unintended users have been added. "
    default_reference = "https://cloud.google.com/iap/docs/managing-access"
    default_severity = Severity.LOW
    log_types = [LogType.GCP_AUDIT_LOG]
    id = "GCP.User.Added.to.IAP.Protected.Service-prototype"

    def rule(self, event):
        return (
            event.deep_get("protoPayload", "methodName", default="")
            == "google.cloud.iap.v1.IdentityAwareProxyAdminService.SetIamPolicy"
        )

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        service = event.deep_get("protoPayload", "request", "resource", default="<RESOURCE_NOT_FOUND>")
        return f"GCP: [{actor}] modified user access to IAP Protected Service [{service}]"

    def alert_context(self, event):
        bindings = event.deep_get("protoPayload", "request", "policy", "bindings", default=[{}])
        return {"bindings": bindings}

    tests = [
        RuleTest(
            name="other",
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
                "protoPayload": {
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
            name="Other IAP Event",
            expected_result=True,
            log={
                "insertId": "46ee5sd38mw",
                "logName": "projects/gcp-project1/logs/cloudaudit.googleapis.com%2Factivity",
                "p_any_emails": ["staging@company.io"],
                "p_any_ip_addresses": ["1.2.3.4"],
                "p_event_time": "2023-04-25 19:20:57.024",
                "p_log_type": "GCP.AuditLog",
                "p_parse_time": "2023-04-25 19:22:14.743",
                "p_row_id": "b2e9b7f5dc85a69981fac2e417b6bb03",
                "p_schema_version": 0,
                "p_source_id": "5b77391b-afad-46c7-8ddc-b8e21d4726b3",
                "p_source_label": "gcplogsource2",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "staging@company.io"},
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "iap.webServices.setIamPolicy",
                            "resourceAttributes": {
                                "name": "projects/123456789012/iap_web/compute/services/7312383563505470445",
                                "service": "iap.googleapis.com",
                                "type": "iap.googleapis.com/WebService",
                            },
                        },
                    ],
                    "methodName": "google.cloud.iap.v1.IdentityAwareProxyAdminService.SetIamPolicy",
                    "request": {
                        "@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest",
                        "policy": {"etag": "BwX6LgT4YMw="},
                        "resource": "projects/123456789012/iap_web/compute/services/7312383563505470445",
                    },
                    "requestMetadata": {
                        "callerIP": "1.2.3.4",
                        "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2023-04-25T19:20:57.295723118Z"},
                    },
                    "resourceName": "projects/123456789012/iap_web/compute/services/7312383563505470445",
                    "response": {"@type": "type.googleapis.com/google.iam.v1.Policy", "etag": "BwX6LgXbpsw="},
                    "serviceName": "iap.googleapis.com",
                },
                "receiveTimestamp": "2023-04-25 19:20:58.16",
                "resource": {
                    "labels": {"backend_service_id": "", "location": "", "project_id": "gcp-project1"},
                    "type": "gce_backend_service",
                },
                "severity": "NOTICE",
                "timestamp": "2023-04-25 19:20:57.024",
            },
        ),
        RuleTest(
            name="Add User to IAP",
            expected_result=True,
            log={
                "insertId": "yyultvcrhy",
                "logName": "projects/gcp-projet1/logs/cloudaudit.googleapis.com%2Factivity",
                "p_any_emails": ["staging@company.io"],
                "p_any_ip_addresses": ["1.2.3.4"],
                "p_event_time": "2023-04-25 19:20:42.138",
                "p_log_type": "GCP.AuditLog",
                "p_parse_time": "2023-04-25 19:22:14.743",
                "p_row_id": "b2e9b7f5dc85a69981fac2e417b7bb03",
                "p_schema_version": 0,
                "p_source_id": "5b77391b-afad-46c7-8ddc-b8e21d4726b3",
                "p_source_label": "gcplogsource2",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "staging@company.io"},
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "iap.webServices.setIamPolicy",
                            "resourceAttributes": {
                                "name": "projects/123456789012/iap_web/compute/services/7312383563505470445",
                                "service": "iap.googleapis.com",
                                "type": "iap.googleapis.com/WebService",
                            },
                        },
                    ],
                    "methodName": "google.cloud.iap.v1.IdentityAwareProxyAdminService.SetIamPolicy",
                    "request": {
                        "@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest",
                        "policy": {
                            "bindings": [
                                {
                                    "members": ["serviceAccount:test-account3@gcp-project1.iam.gserviceaccount.com"],
                                    "role": "roles/viewer",
                                },
                            ],
                            "etag": "ACAB",
                        },
                        "resource": "projects/123456789012/iap_web/compute/services/7312383563505470445",
                    },
                    "requestMetadata": {
                        "callerIP": "1.2.3.4",
                        "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2023-04-25T19:20:42.399215146Z"},
                    },
                    "resourceName": "projects/123456789012/iap_web/compute/services/7312383563505470445",
                    "response": {
                        "@type": "type.googleapis.com/google.iam.v1.Policy",
                        "bindings": [
                            {
                                "members": ["serviceAccount:test-account3@gcp-project1.iam.gserviceaccount.com"],
                                "role": "roles/viewer",
                            },
                        ],
                        "etag": "BwX6LgT4YMw=",
                    },
                    "serviceName": "iap.googleapis.com",
                },
                "receiveTimestamp": "2023-04-25 19:20:43.033",
                "resource": {
                    "labels": {"backend_service_id": "", "location": "", "project_id": "gcp-project1"},
                    "type": "gce_backend_service",
                },
                "severity": "NOTICE",
                "timestamp": "2023-04-25 19:20:42.138",
            },
        ),
    ]
