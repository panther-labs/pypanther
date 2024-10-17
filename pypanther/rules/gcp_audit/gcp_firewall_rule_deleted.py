import re

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPFirewallRuleDeleted(Rule):
    display_name = "GCP Firewall Rule Deleted"
    id = "GCP.Firewall.Rule.Deleted-prototype"
    default_severity = Severity.LOW
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["GCP", "Firewall", "Networking", "Infrastructure"]
    default_description = "This rule detects deletions of GCP firewall rules.\n"
    default_runbook = "Ensure that the rule deletion was expected. Firewall rule deletions can cause service interruptions or outages.\n"
    default_reference = "https://cloud.google.com/firewall/docs/about-firewalls"

    def rule(self, event):
        method_pattern = "(?:\\w+\\.)*v\\d\\.(?:Firewall\\.Delete)|(compute\\.firewalls\\.delete)"
        match = re.search(method_pattern, event.deep_get("protoPayload", "methodName", default=""))
        return match is not None

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        resource = event.deep_get("protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
        resource_id = event.deep_get("resource", "labels", "firewall_rule_id", default="<RESOURCE_ID_NOT_FOUND>")
        if resource_id != "<RESOURCE_ID_NOT_FOUND>":
            return f"[GCP]: [{actor}] deleted firewall rule with resource ID [{resource_id}]"
        return f"[GCP]: [{actor}] deleted firewall rule for resource [{resource}]"

    def alert_context(self, event):
        return gcp_alert_context(event)

    tests = [
        RuleTest(
            name="compute.firewalls-delete-should-alert",
            expected_result=True,
            log={
                "insertid": "-xxxxxxxx",
                "logname": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
                "operation": {
                    "id": "operation-1684869594486-5fc6145ac17b3-6f92b265-43256266",
                    "last": True,
                    "producer": "compute.googleapis.com",
                },
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user@domain.com"},
                    "methodName": "v1.compute.firewalls.delete",
                    "request": {"@type": "type.googleapis.com/compute.firewalls.delete"},
                    "requestMetadata": {
                        "callerIP": "12.12.12.12",
                        "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)",
                    },
                    "resourceName": "projects/test-project-123456/global/firewalls/firewall-create",
                    "serviceName": "compute.googleapis.com",
                },
                "receivetimestamp": "2023-05-23 19:20:00.728",
                "resource": {
                    "labels": {"firewall_rule_id": "6563507997690081088", "project_id": "test-project-123456"},
                    "type": "gce_firewall_rule",
                },
                "severity": "NOTICE",
                "timestamp": "2023-05-23 19:20:00.396",
            },
        ),
        RuleTest(
            name="appengine.firewall.delete-should-alert",
            expected_result=True,
            log={
                "insertid": "-xxxxxxxx",
                "logname": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user@domain.com"},
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "appengine.applications.update",
                            "resource": "apps/test-project-123456/firewall/ingressRules/1000",
                            "resourceAttributes": {},
                        },
                    ],
                    "methodName": "google.appengine.v1.Firewall.DeleteIngressRule",
                    "requestMetadata": {
                        "callerIP": "12.12.12.12",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2023-05-23T19:28:48.805823Z"},
                    },
                    "resourceName": "apps/test-project-123456/firewall/ingressRules/1000",
                    "serviceData": {"@type": "type.googleapis.com/google.appengine.v1beta4.AuditData"},
                    "serviceName": "appengine.googleapis.com",
                    "status": {},
                },
                "receivetimestamp": "2023-05-23 19:28:49.474",
                "resource": {
                    "labels": {"module_id": "", "project_id": "test-project-123456", "version_id": "", "zone": ""},
                    "type": "gae_app",
                },
                "severity": "NOTICE",
                "timestamp": "2023-05-23 19:28:48.707",
            },
        ),
        RuleTest(
            name="compute.non-delete.firewall.method-should-not-alert",
            expected_result=False,
            log={"methodName": "v1.compute.firewalls.insert"},
        ),
        RuleTest(
            name="appengine.non-delete.firewall.method-should-not-alert",
            expected_result=False,
            log={"methodName": "appengine.compute.v1.Firewall.PatchIngressRule"},
        ),
        RuleTest(
            name="randomservice.firewall-delete.method-should-alert",
            expected_result=True,
            log={
                "protoPayload": {
                    "authenticationInfo": {"principalEmail": "user@domain.com"},
                    "methodName": "randomservice.compute.v1.Firewall.DeleteIngressRule",
                    "resourceName": "randomservice/test-project-123456/firewall/ingressRules/1000",
                    "requestMetadata": {
                        "callerIP": "12.12.12.12",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2023-05-23T19:28:44.663413Z"},
                    },
                },
                "resource": {
                    "labels": {"firewall_rule_id": "6563507997690081088", "project_id": "test-project-123456"},
                    "type": "gce_firewall_rule",
                },
            },
        ),
    ]
