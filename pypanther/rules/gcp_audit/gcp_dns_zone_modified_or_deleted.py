from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPDNSZoneModifiedorDeleted(Rule):
    default_description = "Detection for GCP DNS zones that are deleted, patched, or updated."
    display_name = "GCP DNS Zone Modified or Deleted"
    default_runbook = "Verify that this modification or deletion was expected. These operations are high-impact events and can result in downtimes or total outages."
    default_reference = "https://cloud.google.com/dns/docs/zones"
    default_severity = Severity.LOW
    log_types = [LogType.GCP_AUDIT_LOG]
    id = "GCP.DNS.Zone.Modified.or.Deleted-prototype"

    def rule(self, event):
        methods = ("dns.changes.create", "dns.managedZones.delete", "dns.managedZones.patch", "dns.managedZones.update")
        return event.deep_get("protoPayload", "methodName", default="") in methods

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        resource = event.deep_get("protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
        return f"[GCP]: [{actor}] modified managed DNS zone [{resource}]"

    def alert_context(self, event):
        return gcp_alert_context(event)

    tests = [
        RuleTest(
            name="dns.managedZones.delete-should-alert",
            expected_result=True,
            log={
                "insertid": "-xxxxxxxxxxxx",
                "logName": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user@domain.com"},
                    "authorizationInfo": [
                        {"granted": True, "permission": "dns.managedZones.delete", "resourceAttributes": {}},
                    ],
                    "methodName": "dns.managedZones.delete",
                    "request": {
                        "@type": "type.googleapis.com/cloud.dns.api.ManagedZonesDeleteRequest",
                        "managedZone": "test-zone",
                        "project": "test-project-123456",
                    },
                    "requestMetadata": {
                        "callerIP": "12.12.12.12",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2023-05-23T19:08:13.820007Z"},
                    },
                    "resourceName": "managedZones/test-zone",
                    "response": {"@type": "type.googleapis.com/cloud.dns.api.ManagedZonesDeleteResponse"},
                    "serviceName": "dns.googleapis.com",
                    "status": {},
                },
                "receivetimestamp": "2023-05-23 19:08:14.305",
                "resource": {
                    "labels": {"location": "global", "project_id": "test-project-123456", "zone_name": "test-zone"},
                    "type": "dns_managed_zone",
                },
                "severity": "NOTICE",
                "timestamp": "2023-05-23 19:08:11.697",
            },
        ),
        RuleTest(
            name="dns.managedZones.patch-should-alert",
            expected_result=True,
            log={
                "insertid": "-xxxxxxxxxxxx",
                "logname": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user@domain.com"},
                    "authorizationInfo": [
                        {"granted": True, "permission": "dns.managedZones.update", "resourceAttributes": {}},
                    ],
                    "methodName": "dns.managedZones.patch",
                    "request": {
                        "@type": "type.googleapis.com/cloud.dns.api.ManagedZonesPatchRequest",
                        "managedZone": "test-zone",
                        "managedZoneResource": {
                            "description": "testing",
                            "privateVisibilityConfig": {
                                "networks": [
                                    {
                                        "networkUrl": "https://www.googleapis.com/compute/v1/projects/test-project-123456/global/networks/default",
                                    },
                                ],
                            },
                        },
                        "project": "test-project-123456",
                    },
                    "requestMetadata": {
                        "callerIP": "12.12.12.12",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2023-05-23T19:07:25.568071Z"},
                    },
                    "resourceName": "managedZones/test-zone",
                    "response": {
                        "@type": "type.googleapis.com/cloud.dns.api.ManagedZonesPatchResponse",
                        "managedZone": {
                            "cloudLoggingConfig": {},
                            "creationTime": "2023-05-23T18:59:57.919Z",
                            "description": "testing",
                            "dnsName": "test.detectiontesting.com.",
                            "fingerprint": "3f961d0b0a9e6a8c000001884a024eed",
                            "id": "4581881604156058252",
                            "name": "test-zone",
                            "nameServers": ["ns-gcp-private.googledomains.com."],
                            "privateVisibilityConfig": {
                                "networks": [
                                    {
                                        "networkUrl": "https://www.googleapis.com/compute/v1/projects/test-project-123456/global/networks/default",
                                    },
                                ],
                            },
                            "rrsetCount": 2,
                            "visibility": "PRIVATE",
                        },
                        "operation": {
                            "id": "a7513a2c-e637-4b86-b223-1c4f8b0797be",
                            "startTime": "2023-05-23T19:07:25.511Z",
                            "status": "DONE",
                            "type": "UPDATE",
                            "user": "user@domain.com",
                            "zoneContext": {
                                "newValue": {
                                    "cloudLoggingConfig": {},
                                    "creationTime": "2023-05-23T18:59:57.919Z",
                                    "description": "testing",
                                    "dnsName": "test.detectiontesting.com.",
                                    "fingerprint": "3f961d0b0a9e6a8c000001884a024eed",
                                    "id": "4581881604156058252",
                                    "name": "test-zone",
                                    "nameServers": ["ns-gcp-private.googledomains.com."],
                                    "privateVisibilityConfig": {
                                        "networks": [
                                            {
                                                "networkUrl": "https://www.googleapis.com/compute/v1/projects/test-project-123456/global/networks/default",
                                            },
                                        ],
                                    },
                                    "rrsetCount": 2,
                                    "visibility": "PRIVATE",
                                },
                                "oldValue": {
                                    "cloudLoggingConfig": {},
                                    "creationTime": "2023-05-23T18:59:57.919Z",
                                    "description": "testing",
                                    "dnsName": "test.detectiontesting.com.",
                                    "fingerprint": "3f961d0b0a9e6a8c0000018849fb7b5f",
                                    "id": "4581881604156058252",
                                    "name": "test-zone",
                                    "nameServers": ["ns-gcp-private.googledomains.com."],
                                    "rrsetCount": 2,
                                    "visibility": "PRIVATE",
                                },
                            },
                        },
                    },
                    "serviceName": "dns.googleapis.com",
                    "status": {},
                },
                "receivetimestamp": "2023-05-23 19:07:26.276",
                "resource": {
                    "labels": {"location": "global", "project_id": "test-project-123456", "zone_name": "test-zone"},
                    "type": "dns_managed_zone",
                },
                "severity": "NOTICE",
                "timestamp": "2023-05-23 19:07:25.282",
            },
        ),
        RuleTest(
            name="dns.managedZones.update-should-alert",
            expected_result=True,
            log={
                "insertid": "xxxxxxxxxxxx",
                "logname": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user@domain.com"},
                    "authorizationInfo": [
                        {"granted": True, "permission": "dns.changes.create", "resourceAttributes": {}},
                    ],
                    "methodName": "dns.changes.create",
                    "request": {
                        "@type": "type.googleapis.com/cloud.dns.api.ChangesCreateRequest",
                        "change": {
                            "additions": [
                                {
                                    "name": "test.detectiontesting.com.",
                                    "rrdata": [
                                        "ns-gcp-private.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 3600 259200 300",
                                    ],
                                    "ttl": 3600,
                                    "type": "SOA",
                                },
                            ],
                            "deletions": [
                                {
                                    "name": "test.detectiontesting.com.",
                                    "rrdata": [
                                        "ns-gcp-private.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 3600 259200 300",
                                    ],
                                    "ttl": 21600,
                                    "type": "SOA",
                                },
                            ],
                        },
                        "managedZone": "test-zone",
                        "project": "test-project-123456",
                    },
                    "requestMetadata": {
                        "callerIP": "12.12.12.12",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2023-05-23T19:07:39.239275Z"},
                    },
                    "resourceName": "managedZones/test-zone",
                    "response": {
                        "@type": "type.googleapis.com/cloud.dns.api.ChangesCreateResponse",
                        "change": {
                            "additions": [
                                {
                                    "name": "test.detectiontesting.com.",
                                    "rrdata": [
                                        "ns-gcp-private.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 3600 259200 300",
                                    ],
                                    "ttl": 3600,
                                    "type": "SOA",
                                },
                            ],
                            "deletions": [
                                {
                                    "name": "test.detectiontesting.com.",
                                    "rrdata": [
                                        "ns-gcp-private.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 3600 259200 300",
                                    ],
                                    "ttl": 21600,
                                    "type": "SOA",
                                },
                            ],
                            "id": "1",
                            "startTime": "2023-05-23T19:07:39.155Z",
                            "status": "PENDING",
                        },
                    },
                    "serviceName": "dns.googleapis.com",
                    "status": {},
                },
                "receivetimestamp": "2023-05-23 19:07:40.053",
                "resource": {
                    "labels": {"location": "global", "project_id": "test-project-123456", "zone_name": "test-zone"},
                    "type": "dns_managed_zone",
                },
                "severity": "NOTICE",
                "timestamp": "2023-05-23 19:07:39.132",
            },
        ),
        RuleTest(
            name="dns.managedZones.get-should-not-alert",
            expected_result=False,
            log={
                "insertid": "-nkgd1se1zsiw",
                "logName": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "staging@pantherstaging.io"},
                    "authorizationInfo": [
                        {"granted": True, "permission": "dns.managedZones.get", "resourceAttributes": {}},
                    ],
                    "methodName": "dns.managedZones.get",
                    "request": {
                        "@type": "type.googleapis.com/cloud.dns.api.ManagedZonesGetRequest",
                        "managedZone": "test-zone",
                        "project": "test-project-123456",
                    },
                    "requestMetadata": {
                        "callerIP": "12.12.12.12",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2023-05-23T19:08:13.820007Z"},
                    },
                    "resourceName": "managedZones/test-zone",
                    "response": {"@type": "type.googleapis.com/cloud.dns.api.ManagedZonesGetResponse"},
                    "serviceName": "dns.googleapis.com",
                    "status": {},
                },
                "receivetimestamp": "2023-05-23 19:08:14.305",
                "resource": {
                    "labels": {"location": "global", "project_id": "test-project-123456", "zone_name": "test-zone"},
                    "type": "dns_managed_zone",
                },
                "severity": "NOTICE",
                "timestamp": "2023-05-23 19:08:11.697",
            },
        ),
    ]
