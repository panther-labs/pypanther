from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GCPAccessAttemptsViolatingVPCServiceControls(Rule):
    default_description = "An access attempt violating VPC service controls (such as Perimeter controls) has been made."
    display_name = "GCP Access Attempts Violating VPC Service Controls"
    default_reference = "https://cloud.google.com/vpc-service-controls/docs/troubleshooting#debugging"
    default_severity = Severity.MEDIUM
    log_types = [LogType.GCP_AUDIT_LOG]
    id = "GCP.Access.Attempts.Violating.VPC.Service.Controls-prototype"

    def rule(self, event):
        severity = event.get("severity", "")
        status_code = event.deep_get("protoPayload", "status", "code", default="")
        violation_types = event.deep_walk("protoPayload", "status", "details", "violations", "type", default=[])
        if all([severity == "ERROR", status_code == 7, "VPC_SERVICE_CONTROLS" in violation_types]):
            return True
        return False

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        method = event.deep_get("protoPayload", "methodName", default="<METHOD_NOT_FOUND>")
        return f"GCP: [{actor}] performed a [{method}] request that violates VPC Service Controls"

    tests = [
        RuleTest(
            name="Other Event",
            expected_result=False,
            log={
                "insertId": "12345",
                "logName": "projects/test-project/logs/cloudaudit.googleapis.com%2Factivity",
                "operation": {
                    "first": True,
                    "id": "operation-abcdefg-1234567",
                    "last": True,
                    "producer": "compute.googleapis.com",
                },
                "p_any_ip_addresses": ["1.2.3.4"],
                "p_event_time": "2023-03-08 18:52:52.114",
                "p_log_type": "GCP.AuditLog",
                "p_parse_time": "2023-03-08 18:54:14.595",
                "p_row_id": "5e7586fcbb73fdeed985ebeb16bd0c",
                "p_source_id": "4fc88a5a-2d51-4279-9c4a-08fa7cc52566",
                "p_source_label": "gcplogsource",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user1@company.io"},
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "compute.subnetworks.update",
                            "resourceAttributes": {
                                "name": "projects/test-project/regions/us-central1/subnetworks/default",
                                "service": "compute",
                                "type": "compute.subnetworks",
                            },
                        },
                    ],
                    "methodName": "v1.compute.subnetworks.patch",
                    "request": {
                        "@type": "type.googleapis.com/compute.subnetworks.patch",
                        "fingerprint": "/�/��\x03��",
                        "logConfig": {"enable": True},
                    },
                    "requestMetadata": {
                        "callerIP": "1.2.3.4",
                        "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)",
                        "destinationAttributes": {},
                        "requestAttributes": {
                            "auth": {},
                            "reason": "8uSywAYQGg5Db2xpc2V1bSBGbG93cw",
                            "time": "2023-03-08T18:52:52.558899Z",
                        },
                    },
                    "resourceName": "projects/test-project/regions/us-central1/subnetworks/default",
                    "response": {
                        "@type": "type.googleapis.com/operation",
                        "endTime": "2023-03-08T10:52:52.510-08:00",
                        "id": "9876543210",
                        "insertTime": "2023-03-08T10:52:52.509-08:00",
                        "name": "operation-abcdefg-1234567",
                        "operationType": "compute.subnetworks.patch",
                        "progress": "100",
                        "region": "https://www.googleapis.com/compute/v1/projects/test-project/regions/us-central1",
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/test-project/regions/us-central1/operations/operation-abcdefg-1234567",
                        "selfLinkWithId": "https://www.googleapis.com/compute/v1/projects/test-project/regions/us-central1/operations/9876543210",
                        "startTime": "2023-03-08T10:52:52.510-08:00",
                        "status": "DONE",
                        "targetId": "567854321",
                        "targetLink": "https://www.googleapis.com/compute/v1/projects/test-project/regions/us-central1/subnetworks/default",
                        "user": "user1@company.io",
                    },
                    "serviceName": "compute.googleapis.com",
                },
                "receiveTimestamp": "2023-03-08 18:52:52.72",
                "resource": {
                    "labels": {
                        "location": "us-central1",
                        "project_id": "test-project",
                        "subnetwork_id": "567854321",
                        "subnetwork_name": "default",
                    },
                    "type": "gce_subnetwork",
                },
                "severity": "NOTICE",
                "timestamp": "2023-03-08 18:52:52.114",
            },
        ),
        RuleTest(
            name="VPC control violation",
            expected_result=True,
            log={
                "insertId": "13ogcded7jh2",
                "insertid": "15wr7lbb6j",
                "logName": "projects/gcpproject/logs/cloudaudit.googleapis.com%2Fpolicy",
                "logname": "projects/gcpproject/logs/cloudaudit.googleapis.com%2Factivity",
                "p_any_ip_addresses": ["1.2.3.4"],
                "p_event_time": "2023-03-09 10:53:14.929",
                "p_log_type": "GCP.AuditLog",
                "p_parse_time": "2023-03-09 10:54:14.363",
                "p_row_id": "7ad218d42253b7e6f78cc0ed16be37",
                "p_source_id": "4fc88a5a-2d51-4279-9c4a-08fa7cc52566",
                "p_source_label": "gcplogsource",
                "protoPayload": {
                    "at_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user1@serviceaccount.gcp.com"},
                    "metadata": {
                        "at_type": "type.googleapis.com/google.cloud.audit.VpcServiceControlAuditMetadata",
                        "deviceState": "Unknown",
                        "ingressViolations": [
                            {
                                "servicePerimeter": "accessPolicies/123456789012/servicePerimeters/test_perimeter",
                                "targetResource": "projects/197946410614",
                                "targetResourcePermissions": ["NO_PERMISSIONS"],
                            },
                        ],
                        "resourceNames": ["projects/_/buckets/test-restricted-bucket/objects/test1.txt"],
                        "securityPolicyInfo": {
                            "organizationId": "645568414902",
                            "servicePerimeterName": "accessPolicies/123456789012/servicePerimeters/test_perimeter",
                        },
                        "violationReason": "NO_MATCHING_ACCESS_LEVEL",
                        "vpcServiceControlsUniqueId": "gBc-wuGVCapNMnTUePoHos_VyJmr3CsMKlr48kVa4b6XpsT_OWKRng",
                    },
                    "methodName": "google.storage.objects.get",
                    "requestMetadata": {"callerIp": "1.2.3.4", "destinationAttributes": {}, "requestAttributes": {}},
                    "resourceName": "projects/197946410614",
                    "serviceName": "storage.googleapis.com",
                    "status": {
                        "code": 7,
                        "details": [
                            {
                                "at_type": "type.googleapis.com/google.rpc.PreconditionFailure",
                                "violations": [
                                    {
                                        "description": "gBc-wuGVCapNMnTUePoHos_VyJmr3CsMKlr48kVa4b6XpsT_OWKRng",
                                        "type": "VPC_SERVICE_CONTROLS",
                                    },
                                    {
                                        "description": "gCc-wuJa334DJ9940ssdiw_V8400skgjj3912500sldgjzh_LGJANr",
                                        "type": "OTHER_CONTROL_VIOLATION",
                                    },
                                ],
                            },
                        ],
                        "message": "Request is prohibited by organization's policy. vpcServiceControlsUniqueIdentifier: gBc-wuGVCapNMnTUePoHos_VyJmr3CsMKlr48kVa4b6XpsT_OWKRng",
                    },
                },
                "receiveTimestamp": "2023-03-09T16:28:42.567340480Z",
                "resource": {
                    "labels": {
                        "method": "google.storage.objects.get",
                        "project_id": "gcpproject",
                        "service": "storage.googleapis.com",
                    },
                    "type": "audited_resource",
                },
                "severity": "ERROR",
                "timestamp": "2023-03-09T16:28:40.890430163Z",
            },
        ),
    ]
