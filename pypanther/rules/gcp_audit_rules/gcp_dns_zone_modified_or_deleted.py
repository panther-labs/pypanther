from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

gcpdns_zone_modifiedor_deleted_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="dns.managedZones.delete-should-alert",
        ExpectedResult=True,
        Log={
            "insertid": "-xxxxxxxxxxxx",
            "logName": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "user@domain.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "dns.managedZones.delete",
                        "resourceAttributes": {},
                    }
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
                "response": {
                    "@type": "type.googleapis.com/cloud.dns.api.ManagedZonesDeleteResponse"
                },
                "serviceName": "dns.googleapis.com",
                "status": {},
            },
            "receivetimestamp": "2023-05-23 19:08:14.305",
            "resource": {
                "labels": {
                    "location": "global",
                    "project_id": "test-project-123456",
                    "zone_name": "test-zone",
                },
                "type": "dns_managed_zone",
            },
            "severity": "NOTICE",
            "timestamp": "2023-05-23 19:08:11.697",
        },
    ),
    PantherRuleTest(
        Name="dns.managedZones.patch-should-alert",
        ExpectedResult=True,
        Log={
            "insertid": "-xxxxxxxxxxxx",
            "logname": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "user@domain.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "dns.managedZones.update",
                        "resourceAttributes": {},
                    }
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
                                    "networkUrl": "https://www.googleapis.com/compute/v1/projects/test-project-123456/global/networks/default"
                                }
                            ]
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
                                    "networkUrl": "https://www.googleapis.com/compute/v1/projects/test-project-123456/global/networks/default"
                                }
                            ]
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
                                            "networkUrl": "https://www.googleapis.com/compute/v1/projects/test-project-123456/global/networks/default"
                                        }
                                    ]
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
                "labels": {
                    "location": "global",
                    "project_id": "test-project-123456",
                    "zone_name": "test-zone",
                },
                "type": "dns_managed_zone",
            },
            "severity": "NOTICE",
            "timestamp": "2023-05-23 19:07:25.282",
        },
    ),
    PantherRuleTest(
        Name="dns.managedZones.update-should-alert",
        ExpectedResult=True,
        Log={
            "insertid": "xxxxxxxxxxxx",
            "logname": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "user@domain.com"},
                "authorizationInfo": [
                    {"granted": True, "permission": "dns.changes.create", "resourceAttributes": {}}
                ],
                "methodName": "dns.changes.create",
                "request": {
                    "@type": "type.googleapis.com/cloud.dns.api.ChangesCreateRequest",
                    "change": {
                        "additions": [
                            {
                                "name": "test.detectiontesting.com.",
                                "rrdata": [
                                    "ns-gcp-private.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 3600 259200 300"
                                ],
                                "ttl": 3600,
                                "type": "SOA",
                            }
                        ],
                        "deletions": [
                            {
                                "name": "test.detectiontesting.com.",
                                "rrdata": [
                                    "ns-gcp-private.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 3600 259200 300"
                                ],
                                "ttl": 21600,
                                "type": "SOA",
                            }
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
                                    "ns-gcp-private.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 3600 259200 300"
                                ],
                                "ttl": 3600,
                                "type": "SOA",
                            }
                        ],
                        "deletions": [
                            {
                                "name": "test.detectiontesting.com.",
                                "rrdata": [
                                    "ns-gcp-private.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 3600 259200 300"
                                ],
                                "ttl": 21600,
                                "type": "SOA",
                            }
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
                "labels": {
                    "location": "global",
                    "project_id": "test-project-123456",
                    "zone_name": "test-zone",
                },
                "type": "dns_managed_zone",
            },
            "severity": "NOTICE",
            "timestamp": "2023-05-23 19:07:39.132",
        },
    ),
    PantherRuleTest(
        Name="dns.managedZones.get-should-not-alert",
        ExpectedResult=False,
        Log={
            "insertid": "-nkgd1se1zsiw",
            "logName": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "staging@pantherstaging.io"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "dns.managedZones.get",
                        "resourceAttributes": {},
                    }
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
                "labels": {
                    "location": "global",
                    "project_id": "test-project-123456",
                    "zone_name": "test-zone",
                },
                "type": "dns_managed_zone",
            },
            "severity": "NOTICE",
            "timestamp": "2023-05-23 19:08:11.697",
        },
    ),
]


class GCPDNSZoneModifiedorDeleted(PantherRule):
    Description = "Detection for GCP DNS zones that are deleted, patched, or updated."
    DisplayName = "GCP DNS Zone Modified or Deleted"
    Runbook = "Verify that this modification or deletion was expected. These operations are high-impact events and can result in downtimes or total outages."
    Reference = "https://cloud.google.com/dns/docs/zones"
    Severity = PantherSeverity.Low
    LogTypes = [LogType.GCP_AuditLog]
    RuleID = "GCP.DNS.Zone.Modified.or.Deleted-prototype"
    Tests = gcpdns_zone_modifiedor_deleted_tests

    def rule(self, event):
        methods = (
            "dns.changes.create",
            "dns.managedZones.delete",
            "dns.managedZones.patch",
            "dns.managedZones.update",
        )
        return deep_get(event, "protoPayload", "methodName", default="") in methods

    def title(self, event):
        actor = deep_get(
            event,
            "protoPayload",
            "authenticationInfo",
            "principalEmail",
            default="<ACTOR_NOT_FOUND>",
        )
        resource = deep_get(event, "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
        return f"[GCP]: [{actor}] modified managed DNS zone [{resource}]"

    def alert_context(self, event):
        return gcp_alert_context(event)
