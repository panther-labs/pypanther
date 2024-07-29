from ipaddress import ip_address

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import eks_panther_obj_ref

amazon_eks_audit_multiple403_tests: list[RuleTest] = [
    RuleTest(
        name="Not 403",
        expected_result=False,
        log={
            "annotations": {"authorization.k8s.io/decision": "allow", "authorization.k8s.io/reason": ""},
            "apiVersion": "audit.k8s.io/v1",
            "auditID": "35506555-dffc-4337-b2b1-c4af52b88e18",
            "kind": "Event",
            "level": "Request",
            "objectRef": {
                "apiVersion": "v1",
                "name": "kube-bench-drn4j",
                "namespace": "default",
                "resource": "pods",
                "subresource": "log",
            },
            "p_any_aws_account_ids": ["123412341234"],
            "p_any_aws_arns": [
                "arn:aws:iam::123412341234:role/DevAdministrator",
                "arn:aws:sts::123412341234:assumed-role/DevAdministrator/1669660343296132000",
            ],
            "p_any_ip_addresses": ["5.5.5.5"],
            "p_any_usernames": ["kubernetes-admin"],
            "p_event_time": "2022-11-29 00:09:04.38",
            "p_log_type": "Amazon.EKS.Audit",
            "p_parse_time": "2022-11-29 00:10:25.067",
            "p_row_id": "2e4ab474b0f0f7a4a8fff4f014a9b32a",
            "p_source_id": "4c859cd4-9406-469b-9e0e-c2dc1bee24fa",
            "p_source_label": "example-cluster-eks-logs",
            "requestReceivedTimestamp": "2022-11-29 00:09:04.38",
            "requestURI": "/api/v1/namespaces/default/pods/kube-bench-drn4j/log?container=kube-bench",
            "responseStatus": {"code": 200},
            "sourceIPs": ["5.5.5.5"],
            "stage": "ResponseStarted",
            "stageTimestamp": "2022-11-29 00:09:04.392",
            "user": {
                "extra": {
                    "accessKeyId": ["ASIARLIVEKVNN6Y6J5UW"],
                    "arn": ["arn:aws:sts::123412341234:assumed-role/DevAdministrator/1669660343296132000"],
                    "canonicalArn": ["arn:aws:iam::123412341234:role/DevAdministrator"],
                    "sessionName": ["1669660343296132000"],
                },
                "groups": ["system:masters", "system:authenticated"],
                "uid": "aws-iam-authenticator:123412341234:AROARLIVEKVNIRVGDLJWJ",
                "username": "kubernetes-admin",
            },
            "userAgent": "kubectl/v1.25.4 (darwin/arm64) kubernetes/872a965",
            "verb": "get",
        },
    ),
    RuleTest(
        name="403 and Private IP",
        expected_result=False,
        log={
            "annotations": {
                "authorization.k8s.io/decision": "allow",
                "authorization.k8s.io/reason": 'RBAC: allowed by ClusterRoleBinding "system:coredns" of ClusterRole "system:coredns" to ServiceAccount "coredns/kube-system"',
            },
            "apiVersion": "audit.k8s.io/v1",
            "auditID": "e2626946-90e1-4d0c-829e-ad5a78572926",
            "kind": "Event",
            "level": "Metadata",
            "objectRef": {"apiGroup": "discovery.k8s.io", "apiVersion": "v1", "resource": "endpointslices"},
            "p_any_ip_addresses": ["10.0.27.115"],
            "p_any_usernames": ["system:serviceaccount:kube-system:coredns"],
            "p_event_time": "2022-11-29 22:34:06.892",
            "p_log_type": "Amazon.EKS.Audit",
            "p_parse_time": "2022-11-29 22:45:25.024",
            "p_row_id": "c2a7d8dd7c858dcae0a1aaf314b2a207",
            "p_source_id": "4c859cd4-9406-469b-9e0e-c2dc1bee24fa",
            "p_source_label": "example-cluster-eks-logs",
            "requestReceivedTimestamp": "2022-11-29 22:34:06.892",
            "requestURI": "/apis/discovery.k8s.io/v1/endpointslices?allowWatchBookmarks=true&resourceVersion=2528212&timeout=5m56s&timeoutSeconds=356&watch=true",
            "responseStatus": {"code": 403},
            "sourceIPs": ["10.0.27.115"],
            "stage": "ResponseComplete",
            "stageTimestamp": "2022-11-29 22:40:02.903",
            "user": {
                "extra": {
                    "authentication_kubernetes_io_slash_pod-name": ["coredns-57ff979f67-bl27n"],
                    "authentication_kubernetes_io_slash_pod-uid": ["5b9488ae-5563-42aa-850b-b0d82edb3e22"],
                },
                "groups": ["system:serviceaccounts", "system:serviceaccounts:kube-system", "system:authenticated"],
                "uid": "5e4461f9-f529-4e66-9343-0b0cc9452284",
                "username": "system:serviceaccount:kube-system:coredns",
            },
            "userAgent": "Go-http-client/2.0",
            "verb": "watch",
        },
    ),
    RuleTest(
        name="403 and Public IP",
        expected_result=True,
        log={
            "annotations": {
                "authorization.k8s.io/decision": "allow",
                "authorization.k8s.io/reason": 'RBAC: allowed by ClusterRoleBinding "system:coredns" of ClusterRole "system:coredns" to ServiceAccount "coredns/kube-system"',
            },
            "apiVersion": "audit.k8s.io/v1",
            "auditID": "e2626946-90e1-4d0c-829e-ad5a78572926",
            "kind": "Event",
            "level": "Metadata",
            "objectRef": {"apiGroup": "discovery.k8s.io", "apiVersion": "v1", "resource": "endpointslices"},
            "p_any_ip_addresses": ["5.5.5.5"],
            "p_any_usernames": ["system:serviceaccount:kube-system:coredns"],
            "p_event_time": "2022-11-29 22:34:06.892",
            "p_log_type": "Amazon.EKS.Audit",
            "p_parse_time": "2022-11-29 22:45:25.024",
            "p_row_id": "c2a7d8dd7c858dcae0a1aaf314b2a207",
            "p_source_id": "4c859cd4-9406-469b-9e0e-c2dc1bee24fa",
            "p_source_label": "example-cluster-eks-logs",
            "requestReceivedTimestamp": "2022-11-29 22:34:06.892",
            "requestURI": "/apis/discovery.k8s.io/v1/endpointslices?allowWatchBookmarks=true&resourceVersion=2528212&timeout=5m56s&timeoutSeconds=356&watch=true",
            "responseStatus": {"code": 403},
            "sourceIPs": ["5.5.5.5"],
            "stage": "ResponseComplete",
            "stageTimestamp": "2022-11-29 22:40:02.903",
            "user": {
                "extra": {
                    "authentication_kubernetes_io_slash_pod-name": ["coredns-57ff979f67-bl27n"],
                    "authentication_kubernetes_io_slash_pod-uid": ["5b9488ae-5563-42aa-850b-b0d82edb3e22"],
                },
                "groups": ["system:serviceaccounts", "system:serviceaccounts:kube-system", "system:authenticated"],
                "uid": "5e4461f9-f529-4e66-9343-0b0cc9452284",
                "username": "system:serviceaccount:kube-system:coredns",
            },
            "userAgent": "Go-http-client/2.0",
            "verb": "watch",
        },
    ),
]


@panther_managed
class AmazonEKSAuditMultiple403(Rule):
    id = "Amazon.EKS.Audit.Multiple403-prototype"
    display_name = "EKS Audit Log based single sourceIP is generating multiple 403s"
    log_types = [LogType.AMAZON_EKS_AUDIT]
    tags = ["EKS"]
    reports = {"MITRE ATT&CK": ["TA0007:T1613"]}
    default_reference = "https://aws.github.io/aws-eks-best-practices/security/docs/detective/"
    default_severity = Severity.INFO
    default_description = (
        "This detection identifies if a public sourceIP is generating multiple 403s with the Kubernetes API server.\n"
    )
    dedup_period_minutes = 30
    threshold = 10
    summary_attributes = ["user:username", "p_any_ip_addresses", "p_source_label"]
    tests = amazon_eks_audit_multiple403_tests
    # Alert if
    #   state is ResponseComplete
    #   sourceIPs[0] is a Public Address
    #   responseStatus:code == 403
    # If not defined, defaults to the rule display name or rule ID.

    def rule(self, event):
        if event.get("stage", "") != "ResponseComplete":
            return False
        # We include only 403
        if event.get("responseStatus", {}).get("code", 0) != 403:
            return False
        # And we only want things that might naively be kubernetes api endpoints
        # we do not want to alert on scanners casting non-kubernetes requests.
        if not event.get("requestURI", "").startswith(("/api/", "/apis/")):
            return False
        p_eks = eks_panther_obj_ref(event)
        if not ip_address(p_eks.get("sourceIPs")[0]).is_global:
            return False
        return True

    def title(self, event):
        p_eks = eks_panther_obj_ref(event)
        return f"[{p_eks.get('sourceIPs')[0]}] received [403] when executing [{p_eks.get('verb')}] for resource [{p_eks.get('resource')}] in ns [{p_eks.get('ns')}] on [{p_eks.get('p_source_label')}] as [{p_eks.get('actor')}]"

    def dedup(self, event):
        p_eks = eks_panther_obj_ref(event)
        return f"{p_eks.get('p_source_label')}_403_{p_eks.get('sourceIPs')[0]}"

    def alert_context(self, event):
        p_eks = eks_panther_obj_ref(event)
        mutable_event = event.to_dict()
        mutable_event["p_eks"] = p_eks
        return dict(mutable_event)
