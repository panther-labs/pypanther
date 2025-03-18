from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context, get_binding_deltas


@panther_managed
class GCPComputeIAMPolicyUpdate(Rule):
    display_name = "GCP Compute IAM Policy Update Detection"
    id = "GCP.Compute.IAM.Policy.Update-prototype"
    default_severity = Severity.MEDIUM
    log_types = [LogType.GCP_AUDIT_LOG]
    default_description = "This rule detects updates to IAM policies for Compute Disks, Images, and Snapshots.\n"
    default_runbook = (
        "Ensure that the IAM policy update was expected. Unauthorized changes can lead to security risks.\n"
    )
    default_reference = "https://cloud.google.com/compute/docs/access/iam"
    SUSPICIOUS_ACTIONS = [
        "v1.compute.disks.setIamPolicy",
        "v1.compute.images.setIamPolicy",
        "v1.compute.snapshots.setIamPolicy",
    ]

    def rule(self, event):
        if event.deep_get("protoPayload", "response", "error"):
            return False
        method = event.deep_get("protoPayload", "methodName", default="METHOD_NOT_FOUND")
        if method in self.SUSPICIOUS_ACTIONS:
            return True
        return False

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        items = event.deep_get("protoPayload", "methodName", default="ITEMS_NOT_FOUND. ").split(".")[-2]
        project = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: [{actor}] updated IAM policy for [{items}] on project [{project}]"

    def alert_context(self, event):
        context = gcp_alert_context(event)
        service_accounts = event.deep_get("protoPayload", "request", "serviceAccounts")
        if not service_accounts:
            service_account_emails = "<SERVICE_ACCOUNT_EMAILS_NOT_FOUND>"
        else:
            service_account_emails = [service_acc["email"] for service_acc in service_accounts]
        context["serviceAccount"] = service_account_emails
        context["binding_deltas"] = get_binding_deltas(event)
        return context

    tests = [
        RuleTest(
            name="IAM policy update on a Compute Disk",
            expected_result=True,
            log={
                "insertId": "1abcd23efg456",
                "labels": {"compute.googleapis.com/root_trigger_id": "trigger-id-1"},
                "logName": "projects/test-project/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {
                        "principalEmail": "user@example.com",
                        "principalSubject": "serviceAccount:user@example.com",
                        "serviceAccountKeyName": "//iam.googleapis.com/projects/test-project/serviceAccounts/user@example.com/keys/key-id",
                    },
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "compute.disks.setIamPolicy",
                            "resource": "projects/test-project/zones/us-central1-a/disks/disk-1",
                            "resourceAttributes": {
                                "name": "projects/test-project/zones/us-central1-a/disks/disk-1",
                                "service": "compute",
                                "type": "compute.disks",
                            },
                        },
                    ],
                    "methodName": "v1.compute.disks.setIamPolicy",
                    "request": {
                        "@type": "type.googleapis.com/compute.disks.setIamPolicy",
                        "policy": {"bindings": [{"members": ["user:anonymized@example.com"], "role": "roles/owner"}]},
                    },
                    "requestMetadata": {
                        "callerIP": "192.0.2.1",
                        "callerSuppliedUserAgent": "google-cloud-sdk",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2023-10-01T12:34:56.789Z"},
                    },
                    "resourceLocation": {"currentLocations": ["us-central1-a"]},
                    "resourceName": "projects/test-project/zones/us-central1-a/disks/disk-1",
                    "serviceName": "compute.googleapis.com",
                },
                "receiveTimestamp": "2023-10-01T12:34:57.123Z",
                "resource": {
                    "labels": {"disk_id": "disk-id-1", "project_id": "test-project", "zone": "us-central1-a"},
                    "type": "gce_disk",
                },
                "severity": "NOTICE",
                "timestamp": "2023-10-01T12:34:56.789Z",
            },
        ),
        RuleTest(
            name="IAM policy update on a Compute Image",
            expected_result=True,
            log={
                "insertId": "2hijk34lmn789",
                "labels": {"compute.googleapis.com/root_trigger_id": "trigger-id-2"},
                "logName": "projects/test-project/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {
                        "principalEmail": "user@example.com",
                        "principalSubject": "serviceAccount:user@example.com",
                        "serviceAccountKeyName": "//iam.googleapis.com/projects/test-project/serviceAccounts/user@example.com/keys/key-id",
                    },
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "compute.images.setIamPolicy",
                            "resource": "projects/test-project/global/images/image-1",
                            "resourceAttributes": {
                                "name": "projects/test-project/global/images/image-1",
                                "service": "compute",
                                "type": "compute.images",
                            },
                        },
                    ],
                    "methodName": "v1.compute.images.setIamPolicy",
                    "request": {
                        "@type": "type.googleapis.com/compute.images.setIamPolicy",
                        "policy": {"bindings": [{"members": ["user:anonymized@example.com"], "role": "roles/owner"}]},
                    },
                    "requestMetadata": {
                        "callerIP": "192.0.2.2",
                        "callerSuppliedUserAgent": "google-cloud-sdk",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2023-10-01T12:45:56.789Z"},
                    },
                    "resourceLocation": {"currentLocations": ["us-central1-a"]},
                    "resourceName": "projects/test-project/global/images/image-1",
                    "serviceName": "compute.googleapis.com",
                },
                "receiveTimestamp": "2023-10-01T12:45:57.123Z",
                "resource": {"labels": {"image_id": "image-id-1", "project_id": "test-project"}, "type": "gce_image"},
                "severity": "NOTICE",
                "timestamp": "2023-10-01T12:45:56.789Z",
            },
        ),
        RuleTest(
            name="Non-IAM policy update on a Compute Disk",
            expected_result=False,
            log={
                "insertId": "4stuv78wxy345",
                "labels": {"compute.googleapis.com/root_trigger_id": "trigger-id-4"},
                "logName": "projects/test-project/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {
                        "principalEmail": "user@example.com",
                        "principalSubject": "serviceAccount:user@example.com",
                        "serviceAccountKeyName": "//iam.googleapis.com/projects/test-project/serviceAccounts/user@example.com/keys/key-id",
                    },
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "compute.disks.create",
                            "resource": "projects/test-project/zones/us-central1-a/disks/disk-2",
                            "resourceAttributes": {
                                "name": "projects/test-project/zones/us-central1-a/disks/disk-2",
                                "service": "compute",
                                "type": "compute.disks",
                            },
                        },
                    ],
                    "methodName": "v1.compute.disks.create",
                    "requestMetadata": {
                        "callerIP": "192.0.2.4",
                        "callerSuppliedUserAgent": "google-cloud-sdk",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2023-10-01T13:00:00.000Z"},
                    },
                    "resourceLocation": {"currentLocations": ["us-central1-a"]},
                    "resourceName": "projects/test-project/zones/us-central1-a/disks/disk-2",
                    "serviceName": "compute.googleapis.com",
                },
                "receiveTimestamp": "2023-10-01T13:00:01.000Z",
                "resource": {
                    "labels": {"disk_id": "disk-id-2", "project_id": "test-project", "zone": "us-central1-a"},
                    "type": "gce_disk",
                },
                "severity": "NOTICE",
                "timestamp": "2023-10-01T13:00:00.000Z",
            },
        ),
    ]
