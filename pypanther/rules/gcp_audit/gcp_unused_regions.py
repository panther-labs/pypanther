from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.base import deep_get


@panther_managed
class GCPUnusedRegions(Rule):
    id = "GCP.UnusedRegions-prototype"
    display_name = "GCP Resource in Unused Region"
    enabled = False
    dedup_period_minutes = 15
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["GCP", "Database", "Configuration Required", "Defense Evasion:Unused/Unsupported Cloud Regions"]
    reports = {"MITRE ATT&CK": ["TA0005:T1535"]}
    default_severity = Severity.MEDIUM
    default_description = (
        "Adversaries may create cloud instances in unused geographic service regions in order to evade detection.\n"
    )
    default_runbook = "Validate the user making the request and the resource created."
    default_reference = "https://cloud.google.com/docs/geography-and-regions"
    summary_attributes = ["severity", "p_any_ip_addresses", "p_any_domain_names"]
    # 'asia',
    # 'australia',
    # 'eu',
    # 'northamerica',
    # 'southamerica',
    APPROVED_ACTIVE_REGIONS = {"us"}

    def _resource_in_active_region(self, location):
        # return False if location is None, meaning the event did not have a location attribute
        # in any of the places we would expect to find one.
        if location is False:
            return False
        return not any(location.startswith(active_region) for active_region in self.APPROVED_ACTIVE_REGIONS)

    def _get_location_or_zone(self, event):
        resource = event.get("resource")
        if not resource:
            return False
        resource_location = deep_get(resource, "labels", "location")
        if resource_location:
            return resource_location
        resource_zone = deep_get(resource, "labels", "zone")
        if resource_zone:
            return resource_zone
        return False

    def rule(self, event):
        method_name = event.deep_get("protoPayload", "methodName", default="<UNKNOWN_METHOD>")
        if not method_name.endswith(("insert", "create")):
            return False
        return self._resource_in_active_region(self._get_location_or_zone(event))

    def title(self, event):
        return f"GCP resource(s) created in unused region/zone in project {event.deep_get('resource', 'labels', 'project_id', default='<UNKNOWN_PROJECT>')}"

    tests = [
        RuleTest(
            name="GCE Instance Terminated",
            expected_result=False,
            log={
                "logName": "projects/western-verve-225918/logs/cloudaudit.googleapis.com%2Factivity",
                "severity": "NOTICE",
                "insertId": "81xwjyd5vh0",
                "resource": {
                    "type": "gce_instance",
                    "labels": {
                        "instance_id": "5423650206360236277",
                        "project_id": "western-verve-225918",
                        "zone": "europe-north1-a",
                    },
                },
                "timestamp": "2020-05-15 17:55:19.303000000",
                "receiveTimestamp": "2020-05-15 17:55:20.210068584",
                "operation": {
                    "id": "operation-1589565287793-5a5b382538481-3da9816c-ce929997",
                    "producer": "compute.googleapis.com",
                    "last": True,
                },
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "compute.googleapis.com",
                    "methodName": "v1.compute.instances.delete",
                    "resourceName": "projects/western-verve-225918/zones/europe-north1-a/instances/instance-3",
                    "authenticationInfo": {"principalEmail": "jack.naglieri@runpanther.io"},
                    "requestMetadata": {
                        "callerIP": "136.24.229.58",
                        "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36,gzip(gfe),gzip(gfe)",
                    },
                    "request": {"@type": "type.googleapis.com/compute.instances.delete"},
                },
            },
        ),
        RuleTest(
            name="GCE Create Instance in SouthAmerica",
            expected_result=True,
            log={
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user.name@runpanther.io"},
                    "requestMetadata": {
                        "callerIp": "136.24.229.58",
                        "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36,gzip(gfe)",
                    },
                    "serviceName": "compute.googleapis.com",
                    "methodName": "beta.compute.instances.insert",
                    "resourceName": "projects/western-verve-123456/zones/asia-northeast1-b/instances/instance-5",
                    "request": {"@type": "type.googleapis.com/compute.instances.insert"},
                },
                "insertId": "-5tqx5fd4mj8",
                "resource": {
                    "type": "gce_instance",
                    "labels": {
                        "instance_id": "8498166540490993880",
                        "project_id": "western-verve-123456",
                        "zone": "southamerica-east1-b",
                    },
                },
                "timestamp": "2020-05-15T17:15:42.415Z",
                "severity": "NOTICE",
                "logName": "projects/western-verve-123456/logs/cloudaudit.googleapis.com%2Factivity",
                "operation": {
                    "id": "operation-1589562934964-5a5b2f61631d6-cc67597a-98092474",
                    "producer": "compute.googleapis.com",
                    "last": True,
                },
                "receiveTimestamp": "2020-05-15T17:15:43.377082868Z",
            },
        ),
        RuleTest(
            name="Create GCS in Asia",
            expected_result=True,
            log={
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "status": {},
                    "authenticationInfo": {"principalEmail": "user.name@runpanther.io"},
                    "requestMetadata": {
                        "callerIp": "136.24.229.58",
                        "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36,gzip(gfe),gzip(gfe)",
                        "requestAttributes": {"time": "2020-05-15T17:25:07.810848781Z", "auth": {}},
                        "destinationAttributes": {},
                    },
                    "serviceName": "storage.googleapis.com",
                    "methodName": "storage.buckets.create",
                    "authorizationInfo": [
                        {
                            "resource": "projects/_/buckets/jacks-test-bucket-200",
                            "permission": "storage.buckets.create",
                            "granted": True,
                            "resourceAttributes": {},
                        },
                    ],
                    "resourceName": "projects/_/buckets/jacks-test-bucket-200",
                    "serviceData": {
                        "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
                        "policyDelta": {
                            "bindingDeltas": [
                                {
                                    "action": "ADD",
                                    "role": "roles/storage.legacyBucketOwner",
                                    "member": "projectEditor:western-verve-123456",
                                },
                                {
                                    "action": "ADD",
                                    "role": "roles/storage.legacyBucketOwner",
                                    "member": "projectOwner:western-verve-123456",
                                },
                                {
                                    "action": "ADD",
                                    "role": "roles/storage.legacyBucketReader",
                                    "member": "projectViewer:western-verve-123456",
                                },
                            ],
                        },
                    },
                    "request": {
                        "defaultObjectAcl": {
                            "bindings": [
                                {
                                    "role": "roles/storage.legacyObjectReader",
                                    "members": ["projectViewer:western-verve-123456"],
                                },
                                {
                                    "members": [
                                        "projectOwner:western-verve-123456",
                                        "projectEditor:western-verve-123456",
                                    ],
                                    "role": "roles/storage.legacyObjectOwner",
                                },
                            ],
                            "@type": "type.googleapis.com/google.iam.v1.Policy",
                        },
                    },
                    "resourceLocation": {"currentLocations": ["asia-northeast2"]},
                },
                "insertId": "c7rgc9c178",
                "resource": {
                    "type": "gcs_bucket",
                    "labels": {
                        "bucket_name": "jacks-test-bucket-200",
                        "project_id": "western-verve-123456",
                        "location": "asia-northeast2",
                    },
                },
                "timestamp": "2020-05-15T17:25:07.807169539Z",
                "severity": "NOTICE",
                "logName": "projects/western-verve-123456/logs/cloudaudit.googleapis.com%2Factivity",
                "receiveTimestamp": "2020-05-15T17:25:09.393448555Z",
            },
        ),
        RuleTest(
            name="BigQuery access log (does not have standard attribute: resource.labels.location)",
            expected_result=False,
            log={
                "insertId": "v3a96bedw1us",
                "logName": "projects/western-verve-123456/logs/cloudaudit.googleapis.com%2Fdata_access",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user.name@runpanther.io"},
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "bigquery.jobs.create",
                            "resource": "projects/western-verve-123456",
                            "resourceAttributes": {},
                        },
                    ],
                    "methodName": "jobservice.insert",
                    "requestMetadata": {
                        "callerIP": "192.0.2.0",
                        "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:92.0) Gecko/20100101 Firefox/92.0,gzip(gfe),gzip(gfe)",
                        "destinationAttributes": {},
                        "requestAttributes": {},
                    },
                    "resourceName": "projects/western-verve-123456/jobs",
                    "serviceData": {
                        "@type": "type.googleapis.com/google.cloud.bigquery.logging.v1.AuditData",
                        "jobInsertRequest": {
                            "resource": {
                                "jobConfiguration": {
                                    "dryRun": True,
                                    "query": {
                                        "createDisposition": "CREATE_IF_NEEDED",
                                        "defaultDataset": {},
                                        "destinationTable": {},
                                        "query": "select * from no_such_table",
                                        "queryPriority": "QUERY_INTERACTIVE",
                                        "writeDisposition": "WRITE_EMPTY",
                                    },
                                },
                                "jobName": {"location": "US", "projectId": "western-verve-123456"},
                            },
                        },
                        "jobInsertResponse": {
                            "resource": {
                                "jobConfiguration": {},
                                "jobName": {},
                                "jobStatistics": {},
                                "jobStatus": {"error": {}, "state": "PENDING"},
                            },
                        },
                    },
                    "serviceName": "bigquery.googleapis.com",
                    "status": {"code": 11, "message": "Syntax error: Unexpected end of script at [17:7]"},
                },
                "receiveTimestamp": "2021-10-19 16:09:26.351861539",
                "resource": {"labels": {"project_id": "western-verve-123456"}, "type": "bigquery_resource"},
                "severity": "ERROR",
                "timestamp": "2021-10-19 16:09:26.013200000",
            },
        ),
    ]
