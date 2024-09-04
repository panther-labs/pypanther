from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GCPStorageHmacKeysCreate(Rule):
    id = "GCP.Storage.Hmac.Keys.Create-prototype"
    display_name = "GCP storage hmac keys create"
    default_description = "There is a feature of Cloud Storage, “interoperability”, that provides a way for Cloud Storage to interact with storage offerings from other cloud providers, like AWS S3. As part of that, there are HMAC keys that can be created for both Service Accounts and regular users. We can escalate Cloud Storage permissions by creating an HMAC key for a higher-privileged Service Account."
    log_types = [LogType.GCP_AUDIT_LOG]
    default_severity = Severity.HIGH
    default_reference = (
        "https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/"
    )
    reports = {"MITRE ATT&CK": ["TA0004:T1548"]}

    def rule(self, event):
        auth_info = event.deep_walk("protoPayload", "authorizationInfo", default=[])
        auth_info = auth_info if isinstance(auth_info, list) else [auth_info]
        for auth in auth_info:
            if auth.get("granted", False) and auth.get("permission", "") == "storage.hmacKeys.create":
                return True
        return False

    tests = [
        RuleTest(
            name="privilege-escalation",
            expected_result=True,
            log={
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
        RuleTest(
            name="fail",
            expected_result=False,
            log={
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
