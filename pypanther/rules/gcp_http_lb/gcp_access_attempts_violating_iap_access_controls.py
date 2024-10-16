from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GCPAccessAttemptsViolatingIAPAccessControls(Rule):
    default_description = "GCP Access Attempts Violating IAP Access Controls"
    display_name = "GCP Access Attempts Violating IAP Access Controls"
    default_reference = "https://cloud.google.com/iap/docs/concepts-overview"
    default_severity = Severity.MEDIUM
    log_types = [LogType.GCP_HTTP_LOAD_BALANCER]
    id = "GCP.Access.Attempts.Violating.IAP.Access.Controls-prototype"

    def rule(self, event):
        return all(
            [
                event.deep_get("resource", "type", default="") == "http_load_balancer",
                event.deep_get("jsonPayload", "statusDetails", default="") == "handled_by_identity_aware_proxy",
                not any(
                    [
                        str(event.deep_get("httprequest", "status", default=0)).startswith("2"),
                        str(event.deep_get("httprequest", "status", default=0)).startswith("3"),
                    ],
                ),
            ],
        )

    def title(self, event):
        source = event.deep_get("jsonPayload", "remoteIp", default="<SRC_IP_NOT_FOUND>")
        request_url = event.deep_get("httprequest", "requestUrl", default="<REQUEST_URL_NOT_FOUND>")
        return f"GCP: Request Violating IAP controls from [{source}] to [{request_url}]"

    tests = [
        RuleTest(
            name="Blocked By IAP",
            expected_result=True,
            log={
                "httprequest": {
                    "latency": "0.048180s",
                    "remoteIp": "1.2.3.4",
                    "requestMethod": "GET",
                    "requestSize": 77,
                    "requestUrl": "http://6.7.8.9/",
                    "responseSize": 211,
                    "status": 403,
                    "userAgent": "curl/7.85.0",
                },
                "insertid": "u94qwjf25yzns",
                "jsonpayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.loadbalancing.type.LoadBalancerLogEntry",
                    "remoteIp": "1.2.3.4",
                    "statusDetails": "handled_by_identity_aware_proxy",
                },
                "logname": "projects/gcp-project1/logs/requests",
                "p_any_ip_addresses": ["6.7.8.9", "1.2.3.4"],
                "p_any_trace_ids": ["projects/gcp-project1/traces/dd43c6eb7046da54fa3724d2753262e6"],
                "p_event_time": "2023-03-09 23:19:25.712",
                "p_log_type": "GCP.HTTPLoadBalancer",
                "p_parse_time": "2023-03-09 23:21:14.47",
                "p_row_id": "be93fccee09dd2f1b0b2d9ee16d5d704",
                "p_schema_version": 0,
                "p_source_id": "964c7894-9a0d-4ddf-864f-0193438221d6",
                "p_source_label": "panther-gcp-logsource",
                "receivetimestamp": "2023-03-09 23:19:26.392",
                "resource": {
                    "labels": {
                        "backend_service_name": "web-backend-service",
                        "forwarding_rule_name": "http-content-rule",
                        "project_id": "gcp-project1",
                        "target_proxy_name": "http-lb-proxy-2",
                        "url_map_name": "web-map-http-2",
                        "zone": "global",
                    },
                    "type": "http_load_balancer",
                },
                "severity": "INFO",
                "spanid": "d75cc31c93528953",
                "timestamp": "2023-03-09 23:19:25.712",
                "trace": "projects/gcp-project1/traces/dd43c6eb7046da54fa3724d2753262e6",
            },
        ),
        RuleTest(
            name="Redirected by IAP",
            expected_result=False,
            log={
                "httprequest": {
                    "latency": "0.048180s",
                    "remoteIp": "1.2.3.4",
                    "requestMethod": "GET",
                    "requestSize": 77,
                    "requestUrl": "http://6.7.8.9/",
                    "responseSize": 211,
                    "status": 302,
                    "userAgent": "curl/7.85.0",
                },
                "insertid": "u94qwjf25yzns",
                "jsonpayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.loadbalancing.type.LoadBalancerLogEntry",
                    "remoteIp": "1.2.3.4",
                    "statusDetails": "handled_by_identity_aware_proxy",
                },
                "logname": "projects/gcp-project1/logs/requests",
                "p_any_ip_addresses": ["6.7.8.9", "1.2.3.4"],
                "p_any_trace_ids": ["projects/gcp-project1/traces/dd43c6eb7046da54fa3724d2753262e6"],
                "p_event_time": "2023-03-09 23:19:25.712",
                "p_log_type": "GCP.HTTPLoadBalancer",
                "p_parse_time": "2023-03-09 23:21:14.47",
                "p_row_id": "be93fccee09dd2f1b0b2d9ee16d5d704",
                "p_schema_version": 0,
                "p_source_id": "964c7894-9a0d-4ddf-864f-0193438221d6",
                "p_source_label": "panther-gcp-logsource",
                "receivetimestamp": "2023-03-09 23:19:26.392",
                "resource": {
                    "labels": {
                        "backend_service_name": "web-backend-service",
                        "forwarding_rule_name": "http-content-rule",
                        "project_id": "gcp-project1",
                        "target_proxy_name": "http-lb-proxy-2",
                        "url_map_name": "web-map-http-2",
                        "zone": "global",
                    },
                    "type": "http_load_balancer",
                },
                "severity": "INFO",
                "spanid": "d75cc31c93528953",
                "timestamp": "2023-03-09 23:19:25.712",
                "trace": "projects/gcp-project1/traces/dd43c6eb7046da54fa3724d2753262e6",
            },
        ),
    ]
