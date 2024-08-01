from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

gcpiam_org_folder_iam_changes_tests: list[RuleTest] = [
    RuleTest(
        name="Terraform User Agent",
        expected_result=True,
        log={
            "insertId": "-lmjke7dbt7y",
            "logName": "organizations/888888888888/logs/cloudaudit.googleapis.com%2Factivity",
            "p_log_type": "GCP.AuditLog",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {
                    "principalEmail": "terraform@platform.iam.gserviceaccount.com",
                    "principalSubject": "serviceAccount:terraform@platform.iam.gserviceaccount.com",
                    "serviceAccountKeyName": "//iam.googleapis.com/projects/platform/serviceAccounts/terraform@platform.iam.gserviceaccount.com/keys/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                },
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "resourcemanager.organizations.setIamPolicy",
                        "resource": "organizations/888888888888",
                        "resourceAttributes": {
                            "name": "organizations/888888888888",
                            "service": "cloudresourcemanager.googleapis.com",
                            "type": "cloudresourcemanager.googleapis.com/Organization",
                        },
                    },
                ],
                "methodName": "SetIamPolicy",
                "request": {
                    "@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest",
                    "policy": {
                        "bindings": [
                            {
                                "members": [
                                    "joey.jojo@example.com",
                                    "serviceAccount:terraform@platform.iam.gserviceaccount.com",
                                ],
                                "role": "roles/owner",
                            },
                        ],
                        "etag": "BwXcRFUAtX4=",
                    },
                    "resource": "organizations/888888888888",
                    "updateMask": "bindings,etag,auditConfigs",
                },
                "requestMetadata": {
                    "callerIP": "100.100.100.100",
                    "callerSuppliedUserAgent": "Terraform/0.13.2 terraform-provider-google/3.90.1",
                    "destinationAttributes": {},
                    "requestAttributes": {},
                },
                "resourceName": "organizations/888888888888",
                "response": {
                    "@type": "type.googleapis.com/google.iam.v1.Policy",
                    "bindings": [
                        {
                            "members": [
                                "joey.jojo@example.com",
                                "serviceAccount:terraform@platform.iam.gserviceaccount.com",
                            ],
                            "role": "roles/owner",
                        },
                    ],
                    "etag": "BwXeRCtKxCw=",
                },
                "serviceData": {
                    "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
                    "policyDelta": {
                        "bindingDeltas": [
                            {"action": "ADD", "member": "user:backdoor@example.com", "role": "roles/owner"},
                        ],
                    },
                },
                "serviceName": "cloudresourcemanager.googleapis.com",
                "status": {},
            },
            "receiveTimestamp": "2022-05-05 14:00:49.450798551",
            "resource": {"labels": {"organization_id": "888888888888"}, "type": "organization"},
            "severity": "NOTICE",
            "timestamp": "2022-05-05 14:00:48.814294000",
        },
    ),
    RuleTest(
        name="Manual Change",
        expected_result=True,
        log={
            "insertId": "-yoga2udnx8s",
            "logName": "organizations/888888888888/logs/cloudaudit.googleapis.com%2Factivity",
            "p_log_type": "GCP.AuditLog",
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "chris@example.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "resourcemanager.organizations.setIamPolicy",
                        "resource": "organizations/888888888888",
                        "resourceAttributes": {
                            "name": "organizations/888888888888",
                            "service": "cloudresourcemanager.googleapis.com",
                            "type": "cloudresourcemanager.googleapis.com/Organization",
                        },
                    },
                ],
                "methodName": "SetIamPolicy",
                "request": {
                    "@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest",
                    "etag": "BwXYPRNtbqo=",
                    "policy": {
                        "bindings": [
                            {
                                "members": [
                                    "user:chris@example.com",
                                    "serviceAccount:diana@platform.iam.gserviceaccount.com",
                                ],
                                "role": "roles/owner",
                            },
                        ],
                    },
                },
                "receiveTimestamp": "2022-02-17T22:52:03.190032712Z",
                "requestMetadata": {
                    "callerIp": "38.38.38.38",
                    "callerSuppliedUserAgent": "Mozilla/5.0 Chrome/98.0.4758.102",
                    "destinationAttributes": {},
                    "requestAttributes": {},
                },
                "resource": {"labels": {"organization_id": "888888888888"}, "type": "organization"},
                "resourceName": "organizations/888888888888",
                "response": {
                    "@type": "type.googleapis.com/google.iam.v1.Policy",
                    "bindings": [{"members": ["user:chris@example.com"], "role": "roles/owner"}],
                    "etag": "BwXYPp1Xs/Y=",
                },
                "serviceData": {
                    "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
                    "policyDelta": {
                        "bindingDeltas": [
                            {
                                "action": "REMOVE",
                                "member": "serviceAccount:diana@platform.iam.gserviceaccount.com",
                                "role": "roles/owner",
                            },
                        ],
                    },
                },
            },
            "serviceName": "cloudresourcemanager.googleapis.com",
            "severity": "NOTICE",
            "status": {},
            "timestamp": "2022-02-17T22:52:02.692083Z",
        },
    ),
]


@panther_managed
class GCPIAMOrgFolderIAMChanges(Rule):
    id = "GCP.IAM.OrgFolderIAMChanges-prototype"
    display_name = "GCP Org or Folder Policy Was Changed Manually"
    dedup_period_minutes = 1440
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["GCP", "Identity & Access Management"]
    reports = {"GCP_CIS_1.3": ["1.8"], "MITRE ATT&CK": ["Privilege Escalation:Valid Accounts"]}
    default_severity = Severity.HIGH
    default_description = "Alert if a GCP Org or Folder Policy Was Changed Manually.\n"
    default_runbook = "Contact the party that made the change. If it was intended to be temporary, ask for a window for rollback (< 24 hours). If it must be permanent, ask for change-management doc explaining why it was needed. Direct them to make the change in Terraform to avoid automated rollback. Grep for google_org and google_folder in terraform repos for places to put your new policy bindings.\n"
    default_reference = "https://cloud.google.com/iam/docs/granting-changing-revoking-access"
    summary_attributes = ["severity", "p_any_ip_addresses"]
    tests = gcpiam_org_folder_iam_changes_tests

    def rule(self, event):
        # Return True to match the log event and trigger an alert.
        logname = deep_get(event, "logName")
        return (
            deep_get(event, "protoPayload", "methodName") == "SetIamPolicy"
            and (logname.startswith("organizations") or logname.startswith("folder"))
            and logname.endswith("/logs/cloudaudit.googleapis.com%2Factivity")
        )

    def title(self, event):
        # use unified data model field in title
        return f"{event.get('p_log_type')}: [{event.udm('actor_user')}] made manual changes to Org policy"

    def alert_context(self, event):
        return {
            "actor": event.udm("actor_user"),
            "policy_change": deep_get(event, "protoPayload", "serviceData", "policyDelta"),
            "caller_ip": deep_get(event, "protoPayload", "requestMetadata", "callerIP"),
            "user_agent": deep_get(event, "protoPayload", "requestMetadata", "callerSuppliedUserAgent"),
        }

    def severity(self, event):
        if (
            deep_get(event, "protoPayload", "requestMetadata", "callerSuppliedUserAgent").lower().find("terraform")
            != -1
        ):
            return "INFO"
        return "HIGH"
