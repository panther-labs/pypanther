from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.base import deep_get


@panther_managed
class GCPGCSPublic(Rule):
    id = "GCP.GCS.Public-prototype"
    display_name = "GCS Bucket Made Public"
    dedup_period_minutes = 15
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["GCP", "Google Cloud Storage", "Collection:Data From Cloud Storage Object"]
    reports = {"MITRE ATT&CK": ["TA0009:T1530"]}
    default_severity = Severity.HIGH
    default_description = "Adversaries may access data objects from improperly secured cloud storage."
    default_runbook = "Validate the GCS bucket change was safe."
    default_reference = "https://cloud.google.com/storage/docs/access-control/making-data-public"
    summary_attributes = ["severity", "p_any_ip_addresses", "p_any_domain_names"]
    GCS_READ_ROLES = {"roles/storage.objectAdmin", "roles/storage.objectViewer", "roles/storage.admin"}
    GLOBAL_USERS = {"allUsers", "allAuthenticatedUsers"}

    def rule(self, event):
        if event.deep_get("protoPayload", "methodName") != "storage.setIamPermissions":
            return False
        service_data = event.deep_get("protoPayload", "serviceData")
        if not service_data:
            return False
        # Reference: https://cloud.google.com/iam/docs/policies
        binding_deltas = deep_get(service_data, "policyDelta", "bindingDeltas")
        if not binding_deltas:
            return False
        for delta in binding_deltas:
            if delta.get("action") != "ADD":
                continue
            if delta.get("member") in self.GLOBAL_USERS and delta.get("role") in self.GCS_READ_ROLES:
                return True
        return False

    def title(self, event):
        return f"GCS bucket [{event.deep_get('resource', 'labels', 'bucket_name', default='<UNKNOWN_BUCKET>')}] made public"

    tests = [
        RuleTest(
            name="GCS AllUsers Read Permission",
            expected_result=True,
            log={
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "status": {},
                    "authenticationInfo": {"principalEmail": "user.name@runpanther.io"},
                    "requestMetadata": {
                        "callerIp": "136.24.229.58",
                        "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36,gzip(gfe)",
                        "requestAttributes": {"time": "2020-05-15T04:28:42.243082428Z", "auth": {}},
                        "destinationAttributes": {},
                    },
                    "serviceName": "storage.googleapis.com",
                    "methodName": "storage.setIamPermissions",
                    "authorizationInfo": [
                        {
                            "resource": "projects/_/buckets/jacks-test-bucket",
                            "permission": "storage.buckets.setIamPolicy",
                            "granted": True,
                            "resourceAttributes": {},
                        },
                    ],
                    "resourceName": "projects/_/buckets/jacks-test-bucket",
                    "serviceData": {
                        "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
                        "policyDelta": {
                            "bindingDeltas": [
                                {"action": "ADD", "role": "roles/storage.objectViewer", "member": "allUsers"},
                            ],
                        },
                    },
                    "resourceLocation": {"currentLocations": ["us"]},
                },
                "insertId": "15cp9rve72xt1",
                "resource": {
                    "type": "gcs_bucket",
                    "labels": {
                        "bucket_name": "jacks-test-bucket",
                        "project_id": "western-verve-123456",
                        "location": "us",
                    },
                },
                "timestamp": "2020-05-15T04:28:42.237027213Z",
                "severity": "NOTICE",
                "logName": "projects/western-verve-123456/logs/cloudaudit.googleapis.com%2Factivity",
                "receiveTimestamp": "2020-05-15T04:28:42.900626148Z",
            },
        ),
    ]
