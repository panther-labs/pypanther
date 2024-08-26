import re

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get

gcp_firewall_rule_created_tests: list[RuleTest] = [
    RuleTest(
        name="compute.firewalls.create-should-alert",
        expected_result=True,
        log={
            "insertid": "-xxxxxxxxxxxx",
            "logname": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
            "operation": {
                "first": True,
                "id": "operation-1684869580331-5fc6144d418a9-e1332ca3-59c615ac",
                "producer": "compute.googleapis.com",
            },
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "user@domain.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "compute.firewalls.update",
                        "resourceAttributes": {
                            "name": "projects/test-project-123456/global/firewalls/firewall-create",
                            "service": "compute",
                            "type": "compute.firewalls",
                        },
                    },
                    {
                        "granted": True,
                        "permission": "compute.networks.updatePolicy",
                        "resourceAttributes": {
                            "name": "projects/test-project-123456/global/networks/default",
                            "service": "compute",
                            "type": "compute.networks",
                        },
                    },
                ],
                "methodName": "v1.compute.firewalls.insert",
                "request": {
                    "@type": "type.googleapis.com/compute.firewalls.insert",
                    "denieds": [{"IPProtocol": "all"}],
                },
                "requestMetadata": {
                    "callerIP": "12.12.12.12",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)",
                    "destinationAttributes": {},
                    "requestAttributes": {
                        "auth": {},
                        "reason": "8uSywAYQGg5Db2xpc2V1bSBGbG93cw",
                        "time": "2023-05-23T19:19:41.154751Z",
                    },
                },
                "resourceName": "projects/test-project-123456/global/firewalls/firewall-create",
                "response": {
                    "@type": "type.googleapis.com/operation",
                    "id": "896785227463044899",
                    "insertTime": "2023-05-23T12:19:40.876-07:00",
                    "name": "operation-1684869580331-5fc6144d418a9-e1332ca3-59c615ac",
                    "operationType": "patch",
                    "progress": "0",
                    "selfLink": "https://www.googleapis.com/compute/v1/projects/test-project-123456/global/operations/operation-1684869580331-5fc6144d418a9-e1332ca3-59c615ac",
                    "selfLinkWithId": "https://www.googleapis.com/compute/v1/projects/test-project-123456/global/operations/896785227463044899",
                    "startTime": "2023-05-23T12:19:40.888-07:00",
                    "status": "RUNNING",
                    "targetId": "6563507997690081088",
                    "targetLink": "https://www.googleapis.com/compute/v1/projects/test-project-123456/global/firewalls/firewall-create",
                    "user": "user@domain.com",
                },
                "serviceName": "compute.googleapis.com",
            },
            "receivetimestamp": "2023-05-23 19:19:41.238",
            "resource": {
                "labels": {"firewall_rule_id": "6563507997690081088", "project_id": "test-project-123456"},
                "type": "gce_firewall_rule",
            },
            "severity": "NOTICE",
            "timestamp": "2023-05-23 19:19:40.353",
        },
    ),
    RuleTest(
        name="appengine.firewall.create-should-alert",
        expected_result=True,
        log={
            "insertid": "-xxxxxxxxxxxx",
            "logname": "projects/test-project-123456/logs/cloudaudit.googleapis.com%2Factivity",
            "protopayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "user@domain.com"},
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "appengine.applications.update",
                        "resource": "apps/test-project-123456",
                        "resourceAttributes": {},
                    },
                ],
                "methodName": "google.appengine.v1.Firewall.CreateIngressRule",
                "requestMetadata": {
                    "callerIP": "12.12.12.12",
                    "destinationAttributes": {},
                    "requestAttributes": {"auth": {}, "time": "2023-05-23T19:28:35.172216Z"},
                },
                "resourceName": "apps/test-project-123456",
                "serviceData": {"@type": "type.googleapis.com/google.appengine.v1beta4.AuditData"},
                "serviceName": "appengine.googleapis.com",
                "status": {},
            },
            "receivetimestamp": "2023-05-23 19:28:35.479",
            "resource": {
                "labels": {"module_id": "", "project_id": "test-project-123456", "version_id": "", "zone": ""},
                "type": "gae_app",
            },
            "severity": "NOTICE",
            "timestamp": "2023-05-23 19:28:35.049",
        },
    ),
    RuleTest(
        name="compute.non-create.firewall.method-should-not-alert",
        expected_result=False,
        log={"methodName": "v1.compute.firewalls.patch"},
    ),
    RuleTest(
        name="appengine.compute.non-create.firewall.method-should-not-alert",
        expected_result=False,
        log={"methodName": "appengine.compute.v1.Firewall.PatchIngressRule"},
    ),
    RuleTest(
        name="randomservice.firewall-create.method-should-alert",
        expected_result=True,
        log={
            "protoPayload": {
                "authenticationInfo": {"principalEmail": "user@domain.com"},
                "methodName": "randomservice.compute.v1.Firewall.CreateIngressRule",
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


@panther_managed
class GCPFirewallRuleCreated(Rule):
    display_name = "GCP Firewall Rule Created"
    id = "GCP.Firewall.Rule.Created-prototype"
    default_severity = Severity.LOW
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["GCP", "Firewall", "Networking", "Infrastructure"]
    default_description = "This rule detects creations of GCP firewall rules.\n"
    default_runbook = "Ensure that the rule creation was expected. Firewall rule creations can expose [vulnerable] resoures to the internet.\n"
    default_reference = "https://cloud.google.com/firewall/docs/about-firewalls"
    tests = gcp_firewall_rule_created_tests

    def rule(self, event):
        method_pattern = "(?:\\w+\\.)*v\\d\\.(?:Firewall\\.Create)|(compute\\.firewalls\\.insert)"
        match = re.search(method_pattern, deep_get(event, "protoPayload", "methodName", default=""))
        return match is not None

    def title(self, event):
        actor = deep_get(event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        resource = deep_get(event, "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
        resource_id = deep_get(event, "resource", "labels", "firewall_rule_id", default="<RESOURCE_ID_NOT_FOUND>")
        if resource_id != "<RESOURCE_ID_NOT_FOUND>":
            return f"[GCP]: [{actor}] created firewall rule with resource ID [{resource_id}]"
        return f"[GCP]: [{actor}] created firewall rule for resource [{resource}]"

    def alert_context(self, event):
        return gcp_alert_context(event)
