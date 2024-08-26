from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

gcp_workforce_pool_createdor_updated_tests: list[RuleTest] = [
    RuleTest(
        name="DeleteWorkforcePool-False",
        expected_result=False,
        log={
            "insertId": "1plwiv7e2lay7",
            "logName": "organizations/123456789012/logs/cloudaudit.googleapis.com%2Factivity",
            "operation": {
                "first": True,
                "id": "locations/global/workforcePools/test-pool/operations/bigar3hp32vamefaukfkaaq000000000",
                "producer": "iam.googleapis.com",
            },
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "user@example.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "iam.workforcePools.delete",
                        "resource": "locations/global/workforcePools/test-pool",
                        "resourceAttributes": {},
                    },
                ],
                "methodName": "google.iam.admin.v1.WorkforcePools.DeleteWorkforcePool",
                "request": {
                    "@type": "type.googleapis.com/google.iam.admin.v1.DeleteWorkforcePoolRequest",
                    "name": "locations/global/workforcePools/test-pool",
                },
                "requestMetadata": {
                    "callerIp": "07da:0994:97fb:8db1:c68f:c109:fcdd:d594",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0,gzip(gfe),gzip(gfe)",
                    "destinationAttributes": {},
                    "requestAttributes": {
                        "auth": {},
                        "reason": "8uSywAYQGg5Db2xpc2V1bSBGbG93cw",
                        "time": "2023-11-17T18:58:52.165673889Z",
                    },
                },
                "resourceName": "locations/global/workforcePools/test-pool",
                "serviceName": "iam.googleapis.com",
            },
            "receiveTimestamp": "2023-11-17T18:58:52.901258022Z",
            "resource": {
                "labels": {
                    "method": "google.iam.admin.v1.WorkforcePools.DeleteWorkforcePool",
                    "service": "iam.googleapis.com",
                },
                "type": "audited_resource",
            },
            "severity": "NOTICE",
            "timestamp": "2023-11-17T18:58:52.158942930Z",
        },
    ),
    RuleTest(
        name="UpdateWorkforcePool-True",
        expected_result=True,
        log={
            "insertId": "1h09dxwe33hgu",
            "logName": "organizations/123456789012/logs/cloudaudit.googleapis.com%2Factivity",
            "operation": {
                "first": True,
                "id": "locations/global/workforcePools/test-pool/operations/bigarg7n32vamefy6ximiaq000000000",
                "producer": "iam.googleapis.com",
            },
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "user@example.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "iam.workforcePools.update",
                        "resource": "locations/global/workforcePools/test-pool",
                        "resourceAttributes": {},
                    },
                ],
                "methodName": "google.iam.admin.v1.WorkforcePools.UpdateWorkforcePool",
                "request": {
                    "@type": "type.googleapis.com/google.iam.admin.v1.UpdateWorkforcePoolRequest",
                    "updateMask": "description,sessionDuration,disabled,displayName",
                    "workforcePool": {
                        "description": "Test pool to facilitate detection writing",
                        "displayName": "Test Pool",
                        "name": "locations/global/workforcePools/test-pool",
                        "sessionDuration": "43200s",
                    },
                },
                "requestMetadata": {
                    "callerIp": "07da:0994:97fb:8db1:c68f:c109:fcdd:d594",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0,gzip(gfe),gzip(gfe)",
                    "destinationAttributes": {},
                    "requestAttributes": {
                        "auth": {},
                        "reason": "8uSywAYQGg5Db2xpc2V1bSBGbG93cw",
                        "time": "2023-11-17T18:53:15.208909504Z",
                    },
                },
                "resourceName": "locations/global/workforcePools/test-pool",
                "serviceName": "iam.googleapis.com",
            },
            "receiveTimestamp": "2023-11-17T18:53:16.523653141Z",
            "resource": {
                "labels": {
                    "method": "google.iam.admin.v1.WorkforcePools.UpdateWorkforcePool",
                    "service": "iam.googleapis.com",
                },
                "type": "audited_resource",
            },
            "severity": "NOTICE",
            "timestamp": "2023-11-17T18:53:15.200613481Z",
        },
    ),
    RuleTest(
        name="CreateWorkforcePool-True",
        expected_result=True,
        log={
            "insertId": "6432zre32u1v",
            "logName": "organizations/123456789012/logs/cloudaudit.googleapis.com%2Factivity",
            "operation": {
                "first": True,
                "id": "locations/global/workforcePools/test-pool/operations/bifqrwxk32vamegiyoqaoeab00000000",
                "producer": "iam.googleapis.com",
            },
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "user@example.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "iam.workforcePools.create",
                        "resource": "organizations/123456789012",
                        "resourceAttributes": {},
                    },
                ],
                "methodName": "google.iam.admin.v1.WorkforcePools.CreateWorkforcePool",
                "request": {
                    "@type": "type.googleapis.com/google.iam.admin.v1.CreateWorkforcePoolRequest",
                    "location": "locations/global",
                    "workforcePool": {
                        "description": "Test pool",
                        "displayName": "Test Pool",
                        "name": "locations/global/workforcePools/test-pool",
                        "parent": "organizations/325169835352",
                        "sessionDuration": "3600s",
                        "state": "ACTIVE",
                    },
                    "workforcePoolId": "test-pool",
                },
                "requestMetadata": {
                    "callerIp": "07da:0994:97fb:8db1:c68f:c109:fcdd:d594",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0,gzip(gfe),gzip(gfe)",
                    "destinationAttributes": {},
                    "requestAttributes": {
                        "auth": {},
                        "reason": "8uSywAYQGg5Db2xpc2V1bSBGbG93cw",
                        "time": "2023-11-17T18:47:53.284817626Z",
                    },
                },
                "resourceName": "organizations/325169835352",
                "serviceName": "iam.googleapis.com",
            },
            "receiveTimestamp": "2023-11-17T18:47:54.138395349Z",
            "resource": {
                "labels": {
                    "method": "google.iam.admin.v1.WorkforcePools.CreateWorkforcePool",
                    "service": "iam.googleapis.com",
                },
                "type": "audited_resource",
            },
            "severity": "NOTICE",
            "timestamp": "2023-11-17T18:47:53.276929945Z",
        },
    ),
]


@panther_managed
class GCPWorkforcePoolCreatedorUpdated(Rule):
    id = "GCP.Workforce.Pool.Created.or.Updated-prototype"
    display_name = "GCP Workforce Pool Created or Updated"
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["Account Manipulation", "Additional Cloud Roles", "GCP", "Privilege Escalation"]
    reports = {"MITRE ATT&CK": ["TA0003:T1136.003", "TA0003:T1098.003", "TA0004:T1098.003"]}
    default_severity = Severity.HIGH
    default_runbook = "Ensure that the Workforce Pool creation or modification was expected. Adversaries may use this to persist or allow additional access or escalate their privilege.\n"
    default_reference = (
        "https://medium.com/google-cloud/detection-of-inbound-sso-persistence-techniques-in-gcp-c56f7b2a588b"
    )
    tests = gcp_workforce_pool_createdor_updated_tests
    METHODS = [
        "google.iam.admin.v1.WorkforcePools.CreateWorkforcePool",
        "google.iam.admin.v1.WorkforcePools.UpdateWorkforcePool",
    ]

    def rule(self, event):
        return event.deep_get("protoPayload", "methodName", default="") in self.METHODS

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        workforce_pool = event.deep_get("protoPayload", "request", "workforcePool", "name", default="").split("/")[-1]
        resource = organization_id = event.deep_get("logName", default="<LOG_NAME_NOT_FOUND>").split("/")
        organization_id = resource[resource.index("organizations") + 1]
        return (
            f"GCP: [{actor}] created or updated workforce pool [{workforce_pool}] in organization [{organization_id}]"
        )

    def alert_context(self, event):
        return event.deep_get("protoPayload", "request", "workforcePool", default={})
