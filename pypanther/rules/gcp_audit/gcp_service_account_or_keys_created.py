from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GCPServiceAccountorKeysCreated(Rule):
    default_description = (
        "Detects when a service account or key is created manually by a user instead of an automated workflow."
    )
    display_name = "GCP Service Account or Keys Created "
    default_reference = "https://cloud.google.com/iam/docs/keys-create-delete"
    default_severity = Severity.LOW
    log_types = [LogType.GCP_AUDIT_LOG]
    id = "GCP.Service.Account.or.Keys.Created-prototype"

    def rule(self, event):
        return all(
            [
                event.deep_get("resource", "type", default="") == "service_account",
                "CreateServiceAccount" in event.deep_get("protoPayload", "methodName", default=""),
                not event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="").endswith(
                    ".gserviceaccount.com",
                ),
            ],
        )

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        target = event.deep_get("resource", "labels", "email_id")
        project = event.deep_get("resource", "labels", "project_id")
        resource = (
            "Service Account Key for"
            if event.deep_get("protoPayload", "methodName", default="") == "google.iam.admin.v1.CreateServiceAccountKey"
            else "Service Account"
        )
        return f"GCP: [{actor}] created {resource} [{target}] in project [{project}]"

    tests = [
        RuleTest(
            name="Created Service Account Key",
            expected_result=True,
            log={
                "insertId": "1iyadj0d5bmj",
                "logName": "projects/gcp-project1/logs/cloudaudit.googleapis.com%2Factivity",
                "p_any_ip_addresses": ["1.2.3.4"],
                "p_event_time": "2023-03-09 15:50:36.148",
                "p_log_type": "GCP.AuditLog",
                "p_parse_time": "2023-03-09 15:52:14.605",
                "p_row_id": "eee460dd2ac5b8a9a6cdfded16ff75",
                "p_source_id": "4fc88a5a-2d51-4279-9c4a-08fa7cc52566",
                "p_source_label": "gcplogsource",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {
                        "principalEmail": "staging@company.io",
                        "principalSubject": "user:staging@company.io",
                    },
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "iam.serviceAccountKeys.create",
                            "resource": "projects/-/serviceAccounts/123456789098765434567",
                            "resourceAttributes": {"name": "projects/-/serviceAccounts/123456789098765434567"},
                        },
                    ],
                    "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
                    "request": {
                        "@type": "type.googleapis.com/google.iam.admin.v1.CreateServiceAccountKeyRequest",
                        "name": "projects/gcp-project1/serviceAccounts/123456789098765434567",
                        "private_key_type": 2,
                    },
                    "requestMetadata": {
                        "callerIP": "1.2.3.4",
                        "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36,gzip(gfe)",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2023-03-09T15:50:36.163986905Z"},
                    },
                    "resourceName": "projects/-/serviceAccounts/123456789098765434567",
                    "response": {
                        "@type": "type.googleapis.com/google.iam.admin.v1.ServiceAccountKey",
                        "key_algorithm": 2,
                        "key_origin": 2,
                        "key_type": 1,
                        "name": "projects/gcp-project1/serviceAccounts/created-service-account@gcp-project1.iam.gserviceaccount.com/keys/69049163b190437ab9279b28e8afa24bb5c5b076",
                        "private_key_type": 2,
                        "valid_after_time": {"seconds": 1678377036.0},
                        "valid_before_time": {"seconds": 253402300799.0},
                    },
                    "serviceName": "iam.googleapis.com",
                    "status": {},
                },
                "receiveTimestamp": "2023-03-09 15:50:37.603",
                "resource": {
                    "labels": {
                        "email_id": "created-service-account@gcp-project1.iam.gserviceaccount.com",
                        "project_id": "gcp-project1",
                        "unique_id": "123456789098765434567",
                    },
                    "type": "service_account",
                },
                "severity": "NOTICE",
                "timestamp": "2023-03-09 15:50:36.148",
            },
        ),
        RuleTest(
            name="Created Service Account",
            expected_result=True,
            log={
                "insertId": "1iyadj0d5bcq",
                "logName": "projects/gcp-project1/logs/cloudaudit.googleapis.com%2Factivity",
                "p_any_ip_addresses": ["1.2.3.4"],
                "p_event_time": "2023-03-09 15:49:21.715",
                "p_log_type": "GCP.AuditLog",
                "p_parse_time": "2023-03-09 15:50:14.612",
                "p_row_id": "9a08afb7bb84d9eef3d98cee16b306",
                "p_source_id": "4fc88a5a-2d51-4279-9c4a-08fa7cc52566",
                "p_source_label": "gcplogsource",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {
                        "principalEmail": "staging@company.io",
                        "principalSubject": "user:staging@company.io",
                    },
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "iam.serviceAccounts.create",
                            "resource": "projects/gcp-project1",
                            "resourceAttributes": {},
                        },
                    ],
                    "methodName": "google.iam.admin.v1.CreateServiceAccount",
                    "request": {
                        "@type": "type.googleapis.com/google.iam.admin.v1.CreateServiceAccountRequest",
                        "account_id": "created-service-account",
                        "name": "projects/gcp-project1",
                        "service_account": {"description": "sa created", "display_name": "created-service-account"},
                    },
                    "requestMetadata": {
                        "callerIP": "1.2.3.4",
                        "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36,gzip(gfe)",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2023-03-09T15:49:21.729005262Z"},
                    },
                    "resourceName": "projects/gcp-project1",
                    "response": {
                        "@type": "type.googleapis.com/google.iam.admin.v1.ServiceAccount",
                        "description": "sa with limited permissions",
                        "display_name": "created-service-account",
                        "email": "created-service-account@gcp-project1.iam.gserviceaccount.com",
                        "etag": "MDEwMjE5MjA=",
                        "name": "projects/gcp-project1/serviceAccounts/created-service-account@gcp-project1.iam.gserviceaccount.com",
                        "oauth2_client_id": "103995727391704507722",
                        "project_id": "gcp-project1",
                        "unique_id": "103995727391704507722",
                    },
                    "serviceName": "iam.googleapis.com",
                    "status": {},
                },
                "receiveTimestamp": "2023-03-09 15:49:22.599",
                "resource": {
                    "labels": {
                        "email_id": "created-service-account@gcp-project1.iam.gserviceaccount.com",
                        "project_id": "gcp-project1",
                        "unique_id": "103995727391704507722",
                    },
                    "type": "service_account",
                },
                "severity": "NOTICE",
                "timestamp": "2023-03-09 15:49:21.715",
            },
        ),
        RuleTest(
            name="Other",
            expected_result=False,
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
    ]
