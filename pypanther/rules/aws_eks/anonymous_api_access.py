from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import eks_panther_obj_ref


@panther_managed
class AmazonEKSAnonymousAPIAccess(Rule):
    id = "Amazon.EKS.AnonymousAPIAccess-prototype"
    display_name = "EKS Anonymous API Access Detected"
    log_types = [LogType.AMAZON_EKS_AUDIT]
    default_severity = Severity.LOW
    reports = {"MITRE ATT&CK": ["TA0001:T1190"]}
    default_description = "This rule detects anonymous API requests made to the Kubernetes API server. In production environments, anonymous access should be disabled to prevent unauthorized access to the API server.\n"
    default_reference = "https://raesene.github.io/blog/2023/03/18/lets-talk-about-anonymous-access-to-Kubernetes/"
    default_runbook = "Check the EKS cluster configuration and ensure that anonymous access to the Kubernetes API server is disabled. This can be done by verifying the  API server arguments and authentication webhook configuration.\n"
    summary_attributes = ["user:username", "p_any_ip_addresses", "p_source_label"]
    tags = ["EKS", "Security Control", "API", "Initial Access:Exploit Public-Facing Application"]

    def rule(self, event):
        src_ip = event.get("sourceIPs", ["0.0.0.0"])  # nosec
        if src_ip == ["127.0.0.1"]:
            return False
        if event.get("userAgent", "") == "ELB-HealthChecker/2.0" and src_ip[0].startswith("10.0."):
            return False
        # Check if the username is set to "system:anonymous", which indicates anonymous access
        if event.deep_get("user", "username") == "system:anonymous":
            return True
        return False

    def title(self, event):
        # For INFO-level events, just group them all together since they're not that interesting
        if self.severity(event) == "INFO":
            return "Failed Annonymous EKS Acces Attempt(s) Detected"
        p_eks = eks_panther_obj_ref(event)
        return f"Anonymous API access detected on Kubernetes API server from [{p_eks.get('sourceIPs')[0]}] to [{event.get('requestURI', 'NO_URI')}] on [{p_eks.get('p_source_label')}]"

    def severity(self, event):
        if event.deep_get("annotations", "authorization.k8s.io/decision") != "allow":
            return "INFO"
        if event.get("requestURI") == "/version":
            return "INFO"
        return "DEFAULT"

    def dedup(self, event):
        # For INFO-level events, just group them all together since they're not that interesting
        if self.severity(event) == "INFO":
            return "no dedup"
        p_eks = eks_panther_obj_ref(event)
        return f"anonymous_access_{p_eks.get('p_source_label')}_{event.get('userAgent')}"

    def alert_context(self, event):
        p_eks = eks_panther_obj_ref(event)
        mutable_event = event.to_dict()
        mutable_event["p_eks"] = p_eks
        return dict(mutable_event)

    tests = [
        RuleTest(
            name="Anonymous API Access",
            expected_result=True,
            log={
                "annotations": {
                    "authorization.k8s.io/decision": "allow",
                    "authorization.k8s.io/reason": "RBAC: allowed by ClusterRoleBinding system:public-info-viewer",
                },
                "apiVersion": "audit.k8s.io/v1",
                "auditID": "abcde12345",
                "kind": "Event",
                "level": "Request",
                "objectRef": {"apiVersion": "v1", "name": "test-pod", "namespace": "default", "resource": "pods"},
                "p_any_aws_account_ids": ["123412341234"],
                "p_any_aws_arns": ["arn:aws:iam::123412341234:role/DevAdministrator"],
                "p_any_ip_addresses": ["8.8.8.8"],
                "p_any_usernames": ["system:anonymous"],
                "p_event_time": "2022-11-29 00:09:04.38",
                "p_log_type": "Amazon.EKS.Audit",
                "p_parse_time": "2022-11-29 00:10:25.067",
                "p_row_id": "2e4ab474b0f0f7a4a8fff4f014a9b32a",
                "p_source_id": "4c859cd4-9406-469b-9e0e-c2dc1bee24fa",
                "p_source_label": "example-cluster-eks-logs",
                "requestReceivedTimestamp": "2022-11-29 00:09:04.38",
                "requestURI": "/api/v1/namespaces/default/pods/test-pod",
                "responseStatus": {"code": 200},
                "sourceIPs": ["8.8.8.8"],
                "stage": "ResponseComplete",
                "user": {"username": "system:anonymous"},
                "userAgent": "kubectl/v1.25.4",
            },
        ),
        RuleTest(
            name="Non-Anonymous API Access",
            expected_result=False,
            log={
                "annotations": {
                    "authorization.k8s.io/decision": "allow",
                    "authorization.k8s.io/reason": "RBAC: allowed by ClusterRoleBinding system:public-info-viewer",
                },
                "apiVersion": "audit.k8s.io/v1",
                "auditID": "abcde12345",
                "kind": "Event",
                "level": "Request",
                "objectRef": {"apiVersion": "v1", "name": "test-pod", "namespace": "default", "resource": "pods"},
                "p_any_aws_account_ids": ["123412341234"],
                "p_any_aws_arns": ["arn:aws:iam::123412341234:role/DevAdministrator"],
                "p_any_ip_addresses": ["8.8.8.8"],
                "p_any_usernames": ["kubernetes-admin"],
                "p_event_time": "2022-11-29 00:09:04.38",
                "p_log_type": "Amazon.EKS.Audit",
                "p_parse_time": "2022-11-29 00:10:25.067",
                "p_row_id": "2e4ab474b0f0f7a4a8fff4f014a9b32a",
                "p_source_id": "4c859cd4-9406-469b-9e0e-c2dc1bee24fa",
                "p_source_label": "example-cluster-eks-logs",
                "requestReceivedTimestamp": "2022-11-29 00:09:04.38",
                "requestURI": "/api/v1/namespaces/default/pods/test-pod",
                "responseStatus": {"code": 200},
                "sourceIPs": ["8.8.8.8"],
                "stage": "ResponseComplete",
                "user": {"username": "kubernetes-admin"},
                "userAgent": "kubectl/v1.25.4",
            },
        ),
        RuleTest(
            name="Anonymous API Access Web Scanner Allowed",
            expected_result=True,
            log={
                "annotations": {
                    "authorization.k8s.io/decision": "allow",
                    "authorization.k8s.io/reason": 'RBAC: allowed by ClusterRoleBinding "system:public-info-viewer" of ClusterRole "system:public-info-viewer" to Group "system:unauthenticated"',
                },
                "apiVersion": "audit.k8s.io/v1",
                "auditID": "d976bfc6-a2bc-49d5-bdeb-074441e0b875",
                "kind": "Event",
                "level": "Metadata",
                "requestReceivedTimestamp": "2024-11-13 18:34:10.595141000",
                "requestURI": "/version",
                "responseStatus": {"code": 200},
                "sourceIPs": ["44.238.138.237"],
                "stage": "ResponseComplete",
                "stageTimestamp": "2024-11-13 18:34:10.595494000",
                "user": {"groups": ["system:unauthenticated"], "username": "system:anonymous"},
                "userAgent": "python-requests/2.31.0",
                "verb": "get",
            },
        ),
        RuleTest(
            name="Anonymous API Access Web Scanner Denied",
            expected_result=True,
            log={
                "annotations": {"authorization.k8s.io/decision": "forbid", "authorization.k8s.io/reason": ""},
                "apiVersion": "audit.k8s.io/v1",
                "auditID": "edf35e8d-92c3-4507-9bc6-4dd9cf068bcf",
                "kind": "Event",
                "level": "Metadata",
                "requestReceivedTimestamp": "2024-11-13 23:50:32.672347000",
                "requestURI": "/vendor/phpunit/src/Util/PHP/eval-stdin.php",
                "responseStatus": {
                    "code": 403,
                    "message": 'forbidden: User "system:anonymous" cannot get path "/vendor/phpunit/src/Util/PHP/eval-stdin.php"',
                    "reason": "Forbidden",
                    "status": "Failure",
                },
                "sourceIPs": ["8.216.81.10"],
                "stage": "ResponseComplete",
                "stageTimestamp": "2024-11-13 23:50:32.673504000",
                "user": {"groups": ["system:unauthenticated"], "username": "system:anonymous"},
                "userAgent": "Custom-AsyncHttpClient",
                "verb": "get",
            },
        ),
    ]
