import re

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get, deep_walk

gcp_log_bucket_or_sink_deleted_tests: list[RuleTest] = [
    RuleTest(
        name="logging-bucket.deleted-should-alert",
        expected_result=True,
        log={
            "insertid": "xxxxxxxxxx",
            "logname": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "user@domain.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "logging.buckets.delete",
                        "resource": "projects/test-project-123456/locations/global/buckets/testloggingbucket",
                        "resourceAttributes": {
                            "name": "projects/test-project-123456/locations/global/buckets/testloggingbucket",
                            "service": "logging.googleapis.com",
                        },
                    },
                ],
                "methodName": "google.logging.v2.ConfigServiceV2.DeleteBucket",
                "request": {
                    "@type": "type.googleapis.com/google.logging.v2.DeleteBucketRequest",
                    "name": "projects/test-project-123456/locations/global/buckets/testloggingbucket",
                },
                "requestMetadata": {
                    "callerIP": "12.12.12.12",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)",
                    "destinationAttributes": {},
                    "requestAttributes": {"auth": {}, "time": "2023-05-23T19:38:36.846070601Z"},
                },
                "resourceName": "projects/test-project-123456/locations/global/buckets/testloggingbucket",
                "serviceName": "logging.googleapis.com",
                "status": {},
            },
            "receivetimestamp": "2023-05-23 19:38:37.59",
            "resource": {
                "labels": {
                    "method": "google.logging.v2.ConfigServiceV2.DeleteBucket",
                    "project_id": "test-project-123456",
                    "service": "logging.googleapis.com",
                },
                "type": "audited_resource",
            },
            "severity": "NOTICE",
            "timestamp": "2023-05-23 19:38:36.838",
        },
    ),
    RuleTest(
        name="logging-sink.deleted-should-alert",
        expected_result=True,
        log={
            "insertid": "xxxxxxxxxx",
            "logname": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "user@domain.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "logging.sinks.delete",
                        "resource": "projects/test-project-123456/sinks/test-1",
                        "resourceAttributes": {
                            "name": "projects/test-project-123456/sinks/test-1",
                            "service": "logging.googleapis.com",
                        },
                    },
                ],
                "methodName": "google.logging.v2.ConfigServiceV2.DeleteSink",
                "request": {
                    "@type": "type.googleapis.com/google.logging.v2.DeleteSinkRequest",
                    "sinkName": "projects/test-project-123456/sinks/test-1",
                },
                "requestMetadata": {
                    "callerIP": "12.12.12.12",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)",
                    "destinationAttributes": {},
                    "requestAttributes": {"auth": {}, "time": "2023-05-23T19:39:15.230304077Z"},
                },
                "resourceName": "projects/test-project-123456/sinks/test-1",
                "serviceName": "logging.googleapis.com",
                "status": {},
            },
            "receivetimestamp": "2023-05-23 19:39:15.565",
            "resource": {
                "labels": {"destination": "", "name": "test-1", "project_id": "test-project-123456"},
                "type": "logging_sink",
            },
            "severity": "NOTICE",
            "timestamp": "2023-05-23 19:39:15.213",
        },
    ),
    RuleTest(
        name="logging-bucket.non-deletion-should-not-alert",
        expected_result=False,
        log={
            "insertid": "xxxxxxxxxx",
            "logname": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "user@domain.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "logging.buckets.get",
                        "resource": "projects/test-project-123456/locations/global/buckets/testloggingbucket",
                        "resourceAttributes": {
                            "name": "projects/test-project-123456/locations/global/buckets/testloggingbucket",
                            "service": "logging.googleapis.com",
                        },
                    },
                ],
                "methodName": "google.logging.v2.ConfigServiceV2.GetBucket",
                "request": {
                    "@type": "type.googleapis.com/google.logging.v2.GetBucketRequest",
                    "name": "projects/test-project-123456/locations/global/buckets/testloggingbucket",
                },
                "requestMetadata": {
                    "callerIP": "12.12.12.12",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)",
                    "destinationAttributes": {},
                    "requestAttributes": {"auth": {}, "time": "2023-05-23T19:38:36.846070601Z"},
                },
                "resourceName": "projects/test-project-123456/locations/global/buckets/testloggingbucket",
                "serviceName": "logging.googleapis.com",
                "status": {},
            },
            "receivetimestamp": "2023-05-23 19:38:37.59",
            "resource": {
                "labels": {
                    "method": "google.logging.v2.ConfigServiceV2.GetBucket",
                    "project_id": "test-project-123456",
                    "service": "logging.googleapis.com",
                },
                "type": "audited_resource",
            },
            "severity": "NOTICE",
            "timestamp": "2023-05-23 19:38:36.838",
        },
    ),
    RuleTest(
        name="logging-sink.non-deletion-should-not-alert",
        expected_result=False,
        log={
            "insertid": "xxxxxxxxxx",
            "logname": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "user@domain.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "logging.sinks.get",
                        "resource": "projects/test-project-123456/sinks/test-1",
                        "resourceAttributes": {
                            "name": "projects/test-project-123456/sinks/test-1",
                            "service": "logging.googleapis.com",
                        },
                    },
                ],
                "methodName": "google.logging.v2.ConfigServiceV2.GetSink",
                "request": {
                    "@type": "type.googleapis.com/google.logging.v2.GetSinkRequest",
                    "sinkName": "projects/test-project-123456/sinks/test-1",
                },
                "requestMetadata": {
                    "callerIP": "12.12.12.12",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)",
                    "destinationAttributes": {},
                    "requestAttributes": {"auth": {}, "time": "2023-05-23T19:39:15.230304077Z"},
                },
                "resourceName": "projects/test-project-123456/sinks/test-1",
                "serviceName": "logging.googleapis.com",
                "status": {},
            },
            "receivetimestamp": "2023-05-23 19:39:15.565",
            "resource": {
                "labels": {"destination": "", "name": "test-1", "project_id": "test-project-123456"},
                "type": "logging_sink",
            },
            "severity": "NOTICE",
            "timestamp": "2023-05-23 19:39:15.213",
        },
    ),
]


@panther_managed
class GCPLogBucketOrSinkDeleted(Rule):
    display_name = "GCP Log Bucket or Sink Deleted"
    id = "GCP.Log.Bucket.Or.Sink.Deleted-prototype"
    default_severity = Severity.MEDIUM
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["GCP", "Logging", "Bucket", "Sink", "Infrastructure"]
    default_description = "This rule detects deletions of GCP Log Buckets or Sinks.\n"
    default_runbook = (
        "Ensure that the bucket or sink deletion was expected. Adversaries may do this to cover their tracks.\n"
    )
    default_reference = "https://cloud.google.com/logging/docs"
    tests = gcp_log_bucket_or_sink_deleted_tests

    def rule(self, event):
        authenticated = deep_walk(event, "protoPayload", "authorizationInfo", "granted", default=False)
        method_pattern = "(?:\\w+\\.)*v\\d\\.(?:ConfigServiceV\\d\\.(?:Delete(Bucket|Sink)))"
        match = re.search(method_pattern, deep_get(event, "protoPayload", "methodName", default=""))
        return authenticated and match is not None

    def title(self, event):
        actor = deep_get(event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        resource = deep_get(event, "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
        return f"[GCP]: [{actor}] deleted logging bucket or sink [{resource}]"

    def alert_context(self, event):
        return gcp_alert_context(event)
