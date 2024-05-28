import re
from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

gcp_logging_sink_modified_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="logging-sink.modifed-should-alert",
        ExpectedResult=True,
        Log={
            "insertid": "6ns26jclap",
            "logname": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "user@domain.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "logging.sinks.update",
                        "resource": "projects/test-project-123456/sinks/test-1",
                        "resourceAttributes": {
                            "name": "projects/test-project-123456/sinks/test-1",
                            "service": "logging.googleapis.com",
                        },
                    }
                ],
                "methodName": "google.logging.v2.ConfigServiceV2.UpdateSink",
                "request": {
                    "@type": "type.googleapis.com/google.logging.v2.UpdateSinkRequest",
                    "sink": {
                        "description": "test",
                        "destination": "logging.googleapis.com/projects/test-project-123456/locations/global/buckets/testloggingbucket",
                        "exclusions": [{"filter": "*", "name": "excludeall"}],
                        "name": "test-1",
                    },
                    "sinkName": "projects/test-project-123456/sinks/test-1",
                    "uniqueWriterIdentity": True,
                    "updateMask": "exclusions",
                },
                "requestMetadata": {
                    "callerIP": "12.12.12.12",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)",
                    "destinationAttributes": {},
                    "requestAttributes": {"auth": {}, "time": "2023-05-23T19:39:07.289670886Z"},
                },
                "resourceName": "projects/test-project-123456/sinks/test-1",
                "serviceName": "logging.googleapis.com",
                "status": {},
            },
            "receiveTimestamp": "2023-05-23 19:39:07.924",
            "resource": {
                "labels": {
                    "destination": "",
                    "name": "test-1",
                    "project_id": "test-project-123456",
                },
                "type": "logging_sink",
            },
            "severity": "NOTICE",
            "timestamp": "2023-05-23 19:39:07.272",
        },
    ),
    PantherRuleTest(
        Name="logging-sink.non-modified-should-not-alert",
        ExpectedResult=False,
        Log={
            "insertid": "6ns26jclap",
            "logname": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "user@domain.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "logging.sinks.list",
                        "resource": "projects/test-project-123456/sinks/test-1",
                        "resourceAttributes": {
                            "name": "projects/test-project-123456/sinks/test-1",
                            "service": "logging.googleapis.com",
                        },
                    }
                ],
                "methodName": "google.logging.v2.ConfigServiceV2.ListSink",
                "request": {
                    "@type": "type.googleapis.com/google.logging.v2.ListSinkRequest",
                    "sink": {
                        "description": "test",
                        "destination": "logging.googleapis.com/projects/test-project-123456/locations/global/buckets/testloggingbucket",
                        "exclusions": [{"filter": "*", "name": "excludeall"}],
                        "name": "test-1",
                    },
                    "sinkName": "projects/test-project-123456/sinks/test-1",
                    "uniqueWriterIdentity": True,
                    "updateMask": "exclusions",
                },
                "requestMetadata": {
                    "callerIP": "12.12.12.12",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)",
                    "destinationAttributes": {},
                    "requestAttributes": {"auth": {}, "time": "2023-05-23T19:39:07.289670886Z"},
                },
                "resourceName": "projects/test-project-123456/sinks/test-1",
                "serviceName": "logging.googleapis.com",
                "status": {},
            },
            "receiveTimestamp": "2023-05-23 19:39:07.924",
            "resource": {
                "labels": {
                    "destination": "",
                    "name": "test-1",
                    "project_id": "test-project-123456",
                },
                "type": "logging_sink",
            },
            "severity": "NOTICE",
            "timestamp": "2023-05-23 19:39:07.272",
        },
    ),
]


class GCPLoggingSinkModified(PantherRule):
    DisplayName = "GCP Logging Sink Modified"
    RuleID = "GCP.Logging.Sink.Modified-prototype"
    Severity = PantherSeverity.Info
    LogTypes = [LogType.GCP_AuditLog]
    Tags = ["GCP", "Logging", "Sink", "Infrastructure"]
    Description = "This rule detects modifications to GCP Log Sinks.\n"
    Runbook = "Ensure that the modification was valid or expected. Adversaries may do this to exfiltrate logs or evade detection.\n"
    Reference = "https://cloud.google.com/logging/docs"
    Tests = gcp_logging_sink_modified_tests

    def rule(self, event):
        method_pattern = "(?:\\w+\\.)*v\\d\\.(?:ConfigServiceV\\d\\.(?:UpdateSink))"
        match = re.search(method_pattern, deep_get(event, "protoPayload", "methodName", default=""))
        return match is not None

    def title(self, event):
        actor = deep_get(
            event,
            "protoPayload",
            "authenticationInfo",
            "principalEmail",
            default="<ACTOR_NOT_FOUND>",
        )
        resource = deep_get(event, "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
        return f"[GCP]: [{actor}] updated logging sink [{resource}]"

    def alert_context(self, event):
        return gcp_alert_context(event)
