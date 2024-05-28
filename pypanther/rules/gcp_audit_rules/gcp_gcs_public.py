from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

gcpgcs_public_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GCS AllUsers Read Permission",
        ExpectedResult=True,
        Log={
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
                    }
                ],
                "resourceName": "projects/_/buckets/jacks-test-bucket",
                "serviceData": {
                    "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
                    "policyDelta": {
                        "bindingDeltas": [
                            {
                                "action": "ADD",
                                "role": "roles/storage.objectViewer",
                                "member": "allUsers",
                            }
                        ]
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
    )
]


class GCPGCSPublic(PantherRule):
    RuleID = "GCP.GCS.Public-prototype"
    DisplayName = "GCS Bucket Made Public"
    DedupPeriodMinutes = 15
    LogTypes = [LogType.GCP_AuditLog]
    Tags = ["GCP", "Google Cloud Storage", "Collection:Data From Cloud Storage Object"]
    Reports = {"MITRE ATT&CK": ["TA0009:T1530"]}
    Severity = PantherSeverity.High
    Description = "Adversaries may access data objects from improperly secured cloud storage."
    Runbook = "Validate the GCS bucket change was safe."
    Reference = "https://cloud.google.com/storage/docs/access-control/making-data-public"
    SummaryAttributes = ["severity", "p_any_ip_addresses", "p_any_domain_names"]
    Tests = gcpgcs_public_tests
    GCS_READ_ROLES = {
        "roles/storage.objectAdmin",
        "roles/storage.objectViewer",
        "roles/storage.admin",
    }
    GLOBAL_USERS = {"allUsers", "allAuthenticatedUsers"}

    def rule(self, event):
        if deep_get(event, "protoPayload", "methodName") != "storage.setIamPermissions":
            return False
        service_data = deep_get(event, "protoPayload", "serviceData")
        if not service_data:
            return False
        # Reference: https://cloud.google.com/iam/docs/policies
        binding_deltas = deep_get(service_data, "policyDelta", "bindingDeltas")
        if not binding_deltas:
            return False
        for delta in binding_deltas:
            if delta.get("action") != "ADD":
                continue
            if (
                delta.get("member") in self.GLOBAL_USERS
                and delta.get("role") in self.GCS_READ_ROLES
            ):
                return True
        return False

    def title(self, event):
        return f"GCS bucket [{deep_get(event, 'resource', 'labels', 'bucket_name', default='<UNKNOWN_BUCKET>')}] made public"
