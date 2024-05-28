from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

gcp_storage_hmac_keys_create_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="privilege-escalation",
        ExpectedResult=True,
        Log={
            "protoPayload": {
                "authorizationInfo": [{"granted": True, "permission": "storage.hmacKeys.create"}],
                "methodName": "v2.deploymentmanager.deployments.insert",
                "serviceName": "deploymentmanager.googleapis.com",
            },
            "receiveTimestamp": "2024-01-19 13:47:19.465856238",
            "resource": {
                "labels": {"name": "test-vm-deployment", "project_id": "panther-threat-research"},
                "type": "deployment",
            },
            "severity": "NOTICE",
            "timestamp": "2024-01-19 13:47:18.279921000",
        },
    ),
    PantherRuleTest(
        Name="fail",
        ExpectedResult=False,
        Log={
            "protoPayload": {
                "authorizationInfo": [{"granted": False, "permission": "storage.hmacKeys.create"}],
                "methodName": "v2.deploymentmanager.deployments.insert",
                "serviceName": "deploymentmanager.googleapis.com",
            },
            "receiveTimestamp": "2024-01-19 13:47:19.465856238",
            "resource": {
                "labels": {"name": "test-vm-deployment", "project_id": "panther-threat-research"},
                "type": "deployment",
            },
            "severity": "NOTICE",
            "timestamp": "2024-01-19 13:47:18.279921000",
        },
    ),
]


class GCPStorageHmacKeysCreate(PantherRule):
    RuleID = "GCP.Storage.Hmac.Keys.Create-prototype"
    DisplayName = "GCP storage hmac keys create"
    Description = "There is a feature of Cloud Storage, “interoperability”, that provides a way for Cloud Storage to interact with storage offerings from other cloud providers, like AWS S3. As part of that, there are HMAC keys that can be created for both Service Accounts and regular users. We can escalate Cloud Storage permissions by creating an HMAC key for a higher-privileged Service Account."
    LogTypes = [LogType.GCP_AuditLog]
    Severity = PantherSeverity.High
    Reference = "https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/"
    Reports = {"MITRE ATT&CK": ["TA0004:T1548"]}
    Tests = gcp_storage_hmac_keys_create_tests

    def rule(self, event):
        auth_info = event.deep_walk("protoPayload", "authorizationInfo", default=[])
        auth_info = auth_info if isinstance(auth_info, list) else [auth_info]
        for auth in auth_info:
            if (
                auth.get("granted", False)
                and auth.get("permission", "") == "storage.hmacKeys.create"
            ):
                return True
        return False
