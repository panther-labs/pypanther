from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

gcp_workload_identity_pool_createdor_updated_tests: list[RuleTest] = [
    RuleTest(
        name="DeleteWorkloadIdentityPoolProvider-False",
        expected_result=False,
        log={
            "insertId": "1h09dxwe33il5",
            "logName": "projects/test-project/logs/cloudaudit.googleapis.com%2Factivity",
            "operation": {
                "first": True,
                "id": "projects/1234567890123/locations/global/workloadIdentityPools/test-pool/operations/bigarrpp32vamefyvthk4ay000000000",
                "producer": "iam.googleapis.com",
            },
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {
                    "principalEmail": "user@example.com",
                    "principalSubject": "user:user@example.com",
                },
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "iam.workloadIdentityPools.delete",
                        "resource": "projects/test-project/locations/global/workloadIdentityPools/test-pool",
                        "resourceAttributes": {},
                    },
                ],
                "methodName": "google.iam.v1.WorkloadIdentityPools.DeleteWorkloadIdentityPool",
                "request": {
                    "@type": "type.googleapis.com/google.iam.v1.DeleteWorkloadIdentityPoolRequest",
                    "name": "projects/test-project/locations/global/workloadIdentityPools/test-pool",
                },
                "requestMetadata": {
                    "callerIp": "07da:0994:97fb:8db1:c68f:c109:fcdd:d594",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0,gzip(gfe)",
                    "destinationAttributes": {},
                    "requestAttributes": {"auth": {}, "time": "2023-11-17T18:58:13.519015485Z"},
                },
                "resourceName": "projects/test-project/locations/global/workloadIdentityPools/test-pool",
                "serviceName": "iam.googleapis.com",
            },
            "receiveTimestamp": "2023-11-17T18:58:14.565078208Z",
            "resource": {
                "labels": {
                    "method": "google.iam.v1.WorkloadIdentityPools.DeleteWorkloadIdentityPool",
                    "project_id": "test-project",
                    "service": "iam.googleapis.com",
                },
                "type": "audited_resource",
            },
            "severity": "NOTICE",
            "timestamp": "2023-11-17T18:58:13.511621185Z",
        },
    ),
    RuleTest(
        name="UpdateWorkloadIdentityPoolProvider-True",
        expected_result=True,
        log={
            "insertId": "1plwiv7e2lak8",
            "logName": "projects/test-project/logs/cloudaudit.googleapis.com%2Factivity",
            "operation": {
                "first": True,
                "id": "projects/1234567890123/locations/global/workloadIdentityPools/test-pool/providers/test-project/operations/bifqr6xo32vameeqtose200000000000",
                "producer": "iam.googleapis.com",
            },
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {
                    "principalEmail": "user@example.com",
                    "principalSubject": "user:user@example.com",
                },
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "iam.workloadIdentityPoolProviders.update",
                        "resource": "projects/test-project/locations/global/workloadIdentityPools/test-pool/providers/test-project",
                        "resourceAttributes": {},
                    },
                ],
                "methodName": "google.iam.v1.WorkloadIdentityPools.UpdateWorkloadIdentityPoolProvider",
                "request": {
                    "@type": "type.googleapis.com/google.iam.v1.UpdateWorkloadIdentityPoolProviderRequest",
                    "updateMask": "displayName,disabled,attributeMapping,attributeCondition,aws.accountId",
                    "workloadIdentityPoolProvider": {
                        "attributeCondition": "'admins' in google.groups",
                        "attributeMapping": {
                            "attribute.aws_role": "assertion.arn.contains('assumed-role') ? assertion.arn.extract('{account_arn}assumed-role/') + 'assumed-role/' + assertion.arn.extract('assumed-role/{role_name}/') : assertion.arn",
                            "google.subject": "assertion.arn",
                        },
                        "aws": {"accountId": "123456789012"},
                        "disabled": False,
                        "displayName": "Test Provider",
                        "name": "projects/test-project/locations/global/workloadIdentityPools/test-pool/providers/test-project",
                    },
                },
                "requestMetadata": {
                    "callerIp": "07da:0994:97fb:8db1:c68f:c109:fcdd:d594",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0,gzip(gfe)",
                    "destinationAttributes": {},
                    "requestAttributes": {"auth": {}, "time": "2023-11-17T18:56:57.745203848Z"},
                },
                "resourceName": "projects/test-project/locations/global/workloadIdentityPools/test-pool/providers/test-project",
                "serviceName": "iam.googleapis.com",
            },
            "receiveTimestamp": "2023-11-17T18:56:58.871491875Z",
            "resource": {
                "labels": {
                    "method": "google.iam.v1.WorkloadIdentityPools.UpdateWorkloadIdentityPoolProvider",
                    "project_id": "test-project",
                    "service": "iam.googleapis.com",
                },
                "type": "audited_resource",
            },
            "severity": "NOTICE",
            "timestamp": "2023-11-17T18:56:57.730630771Z",
        },
    ),
    RuleTest(
        name="CreateWorkloadIdentityPoolProvider-True",
        expected_result=True,
        log={
            "insertId": "11gmdk5e1ne4r",
            "logName": "projects/test-project/logs/cloudaudit.googleapis.com%2Factivity",
            "operation": {
                "first": True,
                "id": "projects/1234567890123/locations/global/workloadIdentityPools/test-pool/providers/test-project/operations/bigarpxj32vamehaqcf5oai000000000",
                "producer": "iam.googleapis.com",
            },
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {
                    "principalEmail": "user@example.com",
                    "principalSubject": "user:user@example.com",
                },
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "iam.workloadIdentityPoolProviders.create",
                        "resource": "projects/test-project/locations/global/workloadIdentityPools/test-pool",
                        "resourceAttributes": {},
                    },
                ],
                "methodName": "google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProvider",
                "request": {
                    "@type": "type.googleapis.com/google.iam.v1.CreateWorkloadIdentityPoolProviderRequest",
                    "parent": "projects/test-project/locations/global/workloadIdentityPools/test-pool",
                    "workloadIdentityPoolProvider": {
                        "attributeCondition": "",
                        "attributeMapping": {
                            "attribute.aws_role": "assertion.arn.contains('assumed-role') ? assertion.arn.extract('{account_arn}assumed-role/') + 'assumed-role/' + assertion.arn.extract('assumed-role/{role_name}/') : assertion.arn",
                            "google.subject": "assertion.arn",
                        },
                        "aws": {"accountId": "123456789012"},
                        "disabled": False,
                        "displayName": "Test Provider",
                    },
                    "workloadIdentityPoolProviderId": "test-project",
                },
                "requestMetadata": {
                    "callerIp": "07da:0994:97fb:8db1:c68f:c109:fcdd:d594",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0,gzip(gfe)",
                    "destinationAttributes": {},
                    "requestAttributes": {"auth": {}, "time": "2023-11-17T18:45:17.961743198Z"},
                },
                "resourceLocation": {"currentLocations": ["global"]},
                "resourceName": "projects/test-project/locations/global/workloadIdentityPools/test-pool",
                "serviceName": "iam.googleapis.com",
            },
            "receiveTimestamp": "2023-11-17T18:45:19.404664001Z",
            "resource": {
                "labels": {
                    "method": "google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProvider",
                    "project_id": "test-project",
                    "service": "iam.googleapis.com",
                },
                "type": "audited_resource",
            },
            "severity": "NOTICE",
            "timestamp": "2023-11-17T18:45:17.952414168Z",
        },
    ),
]


@panther_managed
class GCPWorkloadIdentityPoolCreatedorUpdated(Rule):
    id = "GCP.Workload.Identity.Pool.Created.or.Updated-prototype"
    display_name = "GCP Workload Identity Pool Created or Updated"
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["Account Manipulation", "Additional Cloud Roles", "GCP", "Privilege Escalation"]
    reports = {"MITRE ATT&CK": ["TA0003:T1136.003", "TA0003:T1098.003", "TA0004:T1098.003"]}
    default_severity = Severity.HIGH
    default_runbook = "Ensure that the Workload Identity Pool creation or modification was expected. Adversaries may use this to persist or allow additional access or escalate their privilege.\n"
    default_reference = (
        "https://medium.com/google-cloud/detection-of-inbound-sso-persistence-techniques-in-gcp-c56f7b2a588b"
    )
    tests = gcp_workload_identity_pool_createdor_updated_tests
    METHODS = [
        "google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProvider",
        "google.iam.v1.WorkloadIdentityPools.UpdateWorkloadIdentityPoolProvider",
    ]

    def rule(self, event):
        return event.deep_get("protoPayload", "methodName", default="") in self.METHODS

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        resource = event.deep_get("protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>").split("/")
        workload_identity_pool = resource[resource.index("workloadIdentityPools") + 1]
        project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"GCP: [{actor}] created or updated workforce pool [{workload_identity_pool}] in project [{project_id}]"

    def alert_context(self, event):
        return event.deep_get("protoPayload", "request", "workloadIdentityPoolProvider", default={})
