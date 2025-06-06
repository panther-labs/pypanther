from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GCPPermissionsGrantedtoCreateorManageServiceAccountKey(Rule):
    default_description = "Permissions granted to impersonate a service account. This includes predefined service account IAM roles granted at the parent project, folder or organization-level."
    display_name = "GCP Permissions Granted to Create or Manage Service Account Key"
    default_reference = "https://cloud.google.com/iam/docs/keys-create-delete"
    default_severity = Severity.LOW
    log_types = [LogType.GCP_AUDIT_LOG]
    id = "GCP.Permissions.Granted.to.Create.or.Manage.Service.Account.Key-prototype"
    SERVICE_ACCOUNT_MANAGE_ROLES = ["roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser"]

    def rule(self, event):
        if "SetIAMPolicy" in event.deep_get("protoPayload", "methodName", default=""):
            role = event.deep_walk(
                "protoPayload",
                "serviceData",
                "policyDelta",
                "bindingDeltas",
                "role",
                default="",
                return_val="last",
            )
            action = event.deep_walk(
                "protoPayload",
                "serviceData",
                "policyDelta",
                "bindingDeltas",
                "action",
                default="",
                return_val="last",
            )
            return role in self.SERVICE_ACCOUNT_MANAGE_ROLES and action == "ADD"
        return False

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        target = event.deep_get("resource", "labels", "email_id") or event.deep_get(
            "resource",
            "labels",
            "project_id",
            default="<TARGET_NOT_FOUND>",
        )
        return f"GCP: [{actor}] granted permissions to create or manage service account keys to [{target}]"

    def alert_context(self, event):
        return {"resource": event.get("resource"), "serviceData": event.deep_get("protoPayload", "serviceData")}

    tests = [
        RuleTest(
            name="other event",
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
            name="service account match",
            expected_result=True,
            log={
                "insertId": "hhpfjvdgakc",
                "logName": "projects/gcp-project1/logs/cloudaudit.googleapis.com%2Factivity",
                "p_any_emails": ["user@company.io"],
                "p_any_ip_addresses": ["1.2.3.4"],
                "p_event_time": "2023-04-10 18:36:30.838",
                "p_log_type": "GCP.AuditLog",
                "p_parse_time": "2023-04-10 18:38:14.607",
                "p_row_id": "5286b52d4095c9f1b2e8eabe178f8203",
                "p_schema_version": 0,
                "p_source_id": "5b77391b-afad-46c7-8ddc-b8e21d4726b3",
                "p_source_label": "gcplogsource2",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {
                        "principalEmail": "user@company.io",
                        "principalSubject": "user:user@company.io",
                    },
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "iam.serviceAccounts.setIamPolicy",
                            "resource": "projects/-/serviceAccounts/105537103139416651075",
                            "resourceAttributes": {"name": "projects/-/serviceAccounts/105537103139416651075"},
                        },
                    ],
                    "methodName": "google.iam.admin.v1.SetIAMPolicy",
                    "request": {
                        "@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest",
                        "policy": {
                            "bindings": [
                                {
                                    "members": ["serviceAccount:test-account3@gcp-project1.iam.gserviceaccount.com"],
                                    "role": "roles/iam.serviceAccountTokenCreator",
                                },
                                {
                                    "members": ["serviceAccount:test-account3@gcp-project1.iam.gserviceaccount.com"],
                                    "role": "roles/iam.serviceAccountUser",
                                },
                            ],
                            "etag": "ACAB",
                            "version": 3,
                        },
                        "resource": "projects/gcp-project1/serviceAccounts/105537103139416651075",
                    },
                    "requestMetadata": {
                        "callerIP": "1.2.3.4",
                        "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36,gzip(gfe)",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2023-04-10T18:36:30.994141642Z"},
                    },
                    "resourceName": "projects/-/serviceAccounts/105537103139416651075",
                    "response": {
                        "@type": "type.googleapis.com/google.iam.v1.Policy",
                        "bindings": [
                            {
                                "members": ["serviceAccount:test-account3@gcp-project1.iam.gserviceaccount.com"],
                                "role": "roles/iam.serviceAccountTokenCreator",
                            },
                            {
                                "members": ["serviceAccount:test-account3@gcp-project1.iam.gserviceaccount.com"],
                                "role": "roles/iam.serviceAccountUser",
                            },
                        ],
                        "etag": "BwX4/6dQjX4=",
                        "version": 1,
                    },
                    "serviceData": {
                        "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
                        "policyDelta": {
                            "bindingDeltas": [
                                {
                                    "action": "ADD",
                                    "member": "serviceAccount:test-account3@gcp-project1.iam.gserviceaccount.com",
                                    "role": "roles/iam.serviceAccountTokenCreator",
                                },
                                {
                                    "action": "ADD",
                                    "member": "serviceAccount:test-account3@gcp-project1.iam.gserviceaccount.com",
                                    "role": "roles/iam.serviceAccountUser",
                                },
                            ],
                        },
                    },
                    "serviceName": "iam.googleapis.com",
                    "status": {},
                },
                "receiveTimestamp": "2023-04-10 18:36:32.268",
                "resource": {
                    "labels": {
                        "email_id": "test-account3@gcp-project1.iam.gserviceaccount.com",
                        "project_id": "gcp-project1",
                        "unique_id": "105537103139416651075",
                    },
                    "type": "service_account",
                },
                "severity": "NOTICE",
                "timestamp": "2023-04-10 18:36:30.838",
            },
        ),
    ]
