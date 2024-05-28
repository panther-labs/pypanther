from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

gcpgcsiam_changes_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GCS IAM Change",
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


class GCPGCSIAMChanges(PantherRule):
    RuleID = "GCP.GCS.IAMChanges-prototype"
    DisplayName = "GCP GCS IAM Permission Changes"
    LogTypes = [LogType.GCP_AuditLog]
    Tags = ["GCP", "Google Cloud Storage", "Collection:Data From Cloud Storage Object"]
    Reports = {"CIS": ["2.1"], "MITRE ATT&CK": ["TA0009:T1530"]}
    Severity = PantherSeverity.Low
    Description = "Monitoring changes to Cloud Storage bucket permissions may reduce time to detect and correct permissions on sensitive Cloud Storage bucket and objects inside the bucket.\n"
    Runbook = "Validate the GCS bucket change was safe."
    Reference = "https://cloud.google.com/storage/docs/access-control/iam-permissions"
    SummaryAttributes = ["severity", "p_any_ip_addresses", "p_any_domain_names"]
    Tests = gcpgcsiam_changes_tests

    def rule(self, event):
        return (
            deep_get(event, "resource", "type") == "gcs_bucket"
            and deep_get(event, "protoPayload", "methodName") == "storage.setIamPermissions"
        )

    def dedup(self, event):
        return deep_get(event, "resource", "labels", "project_id", default="<UNKNOWN_PROJECT>")
