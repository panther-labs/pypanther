from ipaddress import ip_address

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import eks_panther_obj_ref


@panther_managed
class AmazonEKSAuditSystemNamespaceFromPublicIP(Rule):
    id = "Amazon.EKS.Audit.SystemNamespaceFromPublicIP-prototype"
    display_name = "EKS Audit Log Reporting system Namespace is Used From A Public IP"
    log_types = [LogType.AMAZON_EKS_AUDIT]
    tags = ["EKS"]
    reports = {"MITRE ATT&CK": ["TA0027:T1475"]}
    default_reference = "https://docs.aws.amazon.com/eks/latest/userguide/network_reqs.html"
    default_severity = Severity.INFO
    create_alert = False
    default_description = 'This detection identifies if an activity is recorded in the Kubernetes audit log where the user:username attribute begins with "system:" or "eks:" and the requests originating IP Address is a Public IP Address\n'
    dedup_period_minutes = 1440
    summary_attributes = ["user:username", "p_source_label"]
    # Explicitly ignore eks:node-manager and eks:addon-manager
    #  which are run as Lambdas and originate from public IPs
    AMZ_PUBLICS = {"eks:addon-manager", "eks:node-manager"}
    # Alert if
    #   the username starts ( with system: or eks: )
    #   and
    #   sourceIPs[0] is a Public Address
    # If not defined, defaults to the rule display name or rule ID.

    def rule(self, event):
        if event.get("stage", "") != "ResponseComplete":
            return False
        # We explicitly ignore 403 here. There is another
        #  detection that monitors for 403 volume-by-originating-ip
        if event.get("responseStatus", {}).get("code", 0) == 403:
            return False
        p_eks = eks_panther_obj_ref(event)
        if (
            p_eks.get("actor") in self.AMZ_PUBLICS
            and ":assumed-role/AWSWesleyClusterManagerLambda"
            in event.deep_get("user", "extra", "arn", default=["not found"])[0]
        ):
            return False
        if (p_eks.get("actor").startswith("system:") or p_eks.get("actor").startswith("eks:")) and ip_address(
            p_eks.get("sourceIPs")[0],
        ).is_global:
            return True
        return False

    def title(self, event):
        p_eks = eks_panther_obj_ref(event)
        return f"[{p_eks.get('actor')}] executed [{p_eks.get('verb')}] for resource [{p_eks.get('resource')}] in ns [{p_eks.get('ns')}] on [{p_eks.get('p_source_label')}] from [{p_eks.get('sourceIPs')[0]}]"

    def dedup(self, event):
        p_eks = eks_panther_obj_ref(event)
        return f"{p_eks.get('p_source_label')}_eks_system_namespace_{p_eks.get('sourceIPs')[0]}"

    def alert_context(self, event):
        p_eks = eks_panther_obj_ref(event)
        mutable_event = event.to_dict()
        mutable_event["p_eks"] = p_eks
        return dict(mutable_event)

    tests = [
        RuleTest(
            name="non-system username",
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
            name="system username - private ip",
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
                "responseStatus": {"code": 200},
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
            name="403 from Public IP zero count",
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
                "responseStatus": {"code": 200},
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
        RuleTest(
            name="system username - public ip - not ResponseComplete",
            expected_result=False,
            log={
                "annotations": {
                    "authorization.k8s.io/decision": "allow",
                    "authorization.k8s.io/reason": 'RBAC: allowed by ClusterRoleBinding "system:coredns" of ClusterRole "system:coredns" to ServiceAccount "coredns/kube-system"',
                },
                "apiVersion": "audit.k8s.io/v1",
                "auditID": "c8c5bc49-cd5d-45d6-999c-b55783c7840f",
                "kind": "Event",
                "level": "Metadata",
                "objectRef": {"apiGroup": "discovery.k8s.io", "apiVersion": "v1", "resource": "endpointslices"},
                "p_any_ip_addresses": ["5.5.5.5"],
                "p_any_usernames": ["system:serviceaccount:kube-system:coredns"],
                "p_event_time": "2022-11-29 22:46:37.995",
                "p_log_type": "Amazon.EKS.Audit",
                "p_parse_time": "2022-11-29 22:50:24.942",
                "p_row_id": "fa229ed1d0b18094f4a1aff3149531",
                "p_source_id": "4c859cd4-9406-469b-9e0e-c2dc1bee24fa",
                "p_source_label": "example-cluster-eks-logs",
                "requestReceivedTimestamp": "2022-11-29 22:46:37.995",
                "requestURI": "/apis/discovery.k8s.io/v1/endpointslices?allowWatchBookmarks=true&resourceVersion=2529923&timeout=6m41s&timeoutSeconds=401&watch=true",
                "responseStatus": {"code": 200},
                "sourceIPs": ["5.5.5.5"],
                "stage": "ResponseStarted",
                "stageTimestamp": "2022-11-29 22:46:38.013",
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
            name="system username - public ip - 403",
            expected_result=False,
            log={
                "annotations": {
                    "authorization.k8s.io/decision": "allow",
                    "authorization.k8s.io/reason": 'RBAC: allowed by ClusterRoleBinding "system:coredns" of ClusterRole "system:coredns" to ServiceAccount "coredns/kube-system"',
                },
                "apiVersion": "audit.k8s.io/v1",
                "auditID": "c8c5bc49-cd5d-45d6-999c-b55783c7840f",
                "kind": "Event",
                "level": "Metadata",
                "objectRef": {"apiGroup": "discovery.k8s.io", "apiVersion": "v1", "resource": "endpointslices"},
                "p_any_ip_addresses": ["5.5.5.5"],
                "p_any_usernames": ["system:serviceaccount:kube-system:coredns"],
                "p_event_time": "2022-11-29 22:46:37.995",
                "p_log_type": "Amazon.EKS.Audit",
                "p_parse_time": "2022-11-29 22:50:24.942",
                "p_row_id": "fa229ed1d0b18094f4a1aff3149531",
                "p_source_id": "4c859cd4-9406-469b-9e0e-c2dc1bee24fa",
                "p_source_label": "example-cluster-eks-logs",
                "requestReceivedTimestamp": "2022-11-29 22:46:37.995",
                "requestURI": "/apis/discovery.k8s.io/v1/endpointslices?allowWatchBookmarks=true&resourceVersion=2529923&timeout=6m41s&timeoutSeconds=401&watch=true",
                "responseStatus": {"code": 403},
                "sourceIPs": ["5.5.5.5"],
                "stage": "ResponseComplete",
                "stageTimestamp": "2022-11-29 22:46:38.013",
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
            name="eks:addon-manager from public ip as lambda",
            expected_result=False,
            log={
                "annotations": {
                    "authorization.k8s.io/decision": "allow",
                    "authorization.k8s.io/reason": 'RBAC: allowed by RoleBinding "eks:addon-manager/kube-system" of Role "eks:addon-manager" to User "eks:addon-manager"',
                },
                "apiVersion": "audit.k8s.io/v1",
                "auditID": "43410f6e-9c19-482b-b2c7-f2cde260b0e9",
                "kind": "Event",
                "level": "Request",
                "objectRef": {
                    "apiGroup": "apps",
                    "apiVersion": "v1",
                    "name": "coredns",
                    "namespace": "kube-system",
                    "resource": "deployments",
                },
                "p_any_aws_account_ids": ["123412341234"],
                "p_any_aws_arns": [
                    "arn:aws:iam::123412341234:role/AWSWesleyClusterManagerLambda-Add-AddonManagerRole-G332QAM69HWF",
                    "arn:aws:sts::123412341234:assumed-role/AWSWesleyClusterManagerLambda-Add-AddonManagerRole-G332QAM69HWF/1669918824986835422",
                ],
                "p_any_ip_addresses": ["35.163.244.48"],
                "p_any_usernames": ["eks:addon-manager"],
                "p_event_time": "2022-12-01 18:20:25.054",
                "p_log_type": "Amazon.EKS.Audit",
                "p_parse_time": "2022-12-01 18:24:24.734",
                "p_row_id": "a22a2e182591cfb8ead2f7f7149215",
                "p_source_id": "4c859cd4-9406-469b-9e0e-c2dc1bee24fa",
                "p_source_label": "example-cluster-eks-logs",
                "requestReceivedTimestamp": "2022-12-01 18:20:25.054",
                "requestURI": "/apis/apps/v1/namespaces/kube-system/deployments/coredns?timeout=10s",
                "responseStatus": {"code": 200},
                "sourceIPs": ["35.163.244.48"],
                "stage": "ResponseComplete",
                "stageTimestamp": "2022-12-01 18:20:25.078",
                "user": {
                    "extra": {
                        "accessKeyId": ["ASIAXXXXXXXXXXXXXXXX"],
                        "arn": [
                            "arn:aws:sts::123412341234:assumed-role/AWSWesleyClusterManagerLambda-Add-AddonManagerRole-G332QAM69HWF/1669918824986835422",
                        ],
                        "canonicalArn": [
                            "arn:aws:iam::123412341234:role/AWSWesleyClusterManagerLambda-Add-AddonManagerRole-G332QAM69HWF",
                        ],
                        "sessionName": ["1669918824986835422"],
                    },
                    "groups": ["system:authenticated"],
                    "uid": "aws-iam-authenticator:123412341234:AROATAVZDPHFJWUSNL3ZV",
                    "username": "eks:addon-manager",
                },
                "userAgent": "Go-http-client/1.1",
                "verb": "get",
            },
        ),
    ]
