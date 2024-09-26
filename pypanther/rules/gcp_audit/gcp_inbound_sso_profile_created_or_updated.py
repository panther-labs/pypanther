from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GCPInboundSSOProfileCreated(Rule):
    id = "GCP.Inbound.SSO.Profile.Created-prototype"
    display_name = "GCP Inbound SSO Profile Created"
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["Account Manipulation", "Additional Cloud Roles", "GCP", "Privilege Escalation"]
    reports = {"MITRE ATT&CK": ["TA0003:T1136.003", "TA0003:T1098.003", "TA0004:T1098.003"]}
    default_severity = Severity.HIGH
    default_runbook = "Ensure that the SSO profile creation or modification was expected. Adversaries may use this to persist or allow additional access or escalate their privilege.\n"
    default_reference = (
        "https://medium.com/google-cloud/detection-of-inbound-sso-persistence-techniques-in-gcp-c56f7b2a588b"
    )
    METHODS = [
        "google.admin.AdminService.inboundSsoProfileCreated",
        "google.admin.AdminService.inboundSsoProfileUpdated",
    ]

    def rule(self, event):
        return event.deep_get("protoPayload", "methodName", default="") in self.METHODS

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        event_name = event.deep_walk("protoPayload", "metadata", "event", "eventName", default="<EVENT_NAME_NOT_FOUND>")
        resource = organization_id = event.deep_walk(
            "protoPayload",
            "resourceName",
            default="<RESOURCE_NOT_FOUND>",
        ).split("/")
        organization_id = resource[resource.index("organizations") + 1]
        return f"GCP: [{actor}] performed {event_name} in organization {organization_id}"

    def alert_context(self, event):
        return {
            "resourceName": event.deep_get("protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>"),
            "serviceName": event.deep_get("protoPayload", "serviceName", default="<SERVICE_NOT_FOUND>"),
        }

    tests = [
        RuleTest(
            name="InboundSsoProfileDeleted-False",
            expected_result=False,
            log={
                "insertId": "chtsf1e7iek8",
                "logName": "organizations/325169835352/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user@example.com"},
                    "metadata": {
                        "@type": "type.googleapis.com/ccc_hosted_reporting.ActivityProto",
                        "activityId": {"timeUsec": "1700250882598435", "uniqQualifier": "6879748717081533837"},
                        "event": [
                            {
                                "eventId": "dd0c44e2",
                                "eventName": "INBOUND_SSO_PROFILE_DELETED",
                                "eventType": "INBOUND_SSO_SETTINGS",
                                "parameter": [
                                    {
                                        "label": "LABEL_OPTIONAL",
                                        "name": "INBOUND_SSO_PROFILE_NAME",
                                        "type": "TYPE_STRING",
                                        "value": "inboundSamlSsoProfiles/01lmf7wd3jt9atc",
                                    },
                                ],
                            },
                        ],
                    },
                    "methodName": "google.admin.AdminService.inboundSsoProfileDeleted",
                    "requestMetadata": {"destinationAttributes": {}, "requestAttributes": {}},
                    "resourceName": "organizations/123456789012/inboundSsoSettings",
                    "serviceName": "admin.googleapis.com",
                },
                "receiveTimestamp": "2023-11-17T19:54:43.367407397Z",
                "resource": {
                    "labels": {
                        "method": "google.admin.AdminService.inboundSsoProfileDeleted",
                        "service": "admin.googleapis.com",
                    },
                    "type": "audited_resource",
                },
                "severity": "NOTICE",
                "timestamp": "2023-11-17T19:54:42.598435Z",
            },
        ),
        RuleTest(
            name="InboundSsoProfileUpdated-True",
            expected_result=True,
            log={
                "insertId": "crpr6bdcjfg",
                "logName": "organizations/123456789012/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user@@example.com"},
                    "metadata": {
                        "@type": "type.googleapis.com/ccc_hosted_reporting.ActivityProto",
                        "activityId": {"timeUsec": "1700250956956215", "uniqQualifier": "2009471038637356014"},
                        "event": [
                            {
                                "eventId": "bdbc47ad",
                                "eventName": "INBOUND_SSO_PROFILE_UPDATED",
                                "eventType": "INBOUND_SSO_SETTINGS",
                                "parameter": [
                                    {
                                        "label": "LABEL_OPTIONAL",
                                        "name": "INBOUND_SSO_PROFILE_CHANGES",
                                        "type": "TYPE_STRING",
                                        "value": "Display Name : { oldValue: Test Profile, newValue: Test Profile Update}",
                                    },
                                    {
                                        "label": "LABEL_OPTIONAL",
                                        "name": "INBOUND_SSO_PROFILE_NAME",
                                        "type": "TYPE_STRING",
                                        "value": "inboundSamlSsoProfiles/03vsz0843d02br4",
                                    },
                                ],
                            },
                        ],
                    },
                    "methodName": "google.admin.AdminService.inboundSsoProfileUpdated",
                    "requestMetadata": {"destinationAttributes": {}, "requestAttributes": {}},
                    "resourceName": "organizations/123456789012/inboundSsoSettings",
                    "serviceName": "admin.googleapis.com",
                },
                "receiveTimestamp": "2023-11-17T19:55:57.417198068Z",
                "resource": {
                    "labels": {
                        "method": "google.admin.AdminService.inboundSsoProfileUpdated",
                        "service": "admin.googleapis.com",
                    },
                    "type": "audited_resource",
                },
                "severity": "NOTICE",
                "timestamp": "2023-11-17T19:55:56.956215Z",
            },
        ),
        RuleTest(
            name="InboundSsoProfileCreated-True",
            expected_result=True,
            log={
                "insertId": "-rqtp5gefopij",
                "logName": "organizations/123456789012/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user@example.com"},
                    "metadata": {
                        "@type": "type.googleapis.com/ccc_hosted_reporting.ActivityProto",
                        "activityId": {"timeUsec": "1700250924521362", "uniqQualifier": "6051731645161637785"},
                        "event": [
                            {
                                "eventId": "637d2b33",
                                "eventName": "INBOUND_SSO_PROFILE_CREATED",
                                "eventType": "INBOUND_SSO_SETTINGS",
                                "parameter": [
                                    {
                                        "label": "LABEL_OPTIONAL",
                                        "name": "INBOUND_SSO_PROFILE_NAME",
                                        "type": "TYPE_STRING",
                                        "value": "inboundSamlSsoProfiles/03vsz0843d02br4",
                                    },
                                ],
                            },
                        ],
                    },
                    "methodName": "google.admin.AdminService.inboundSsoProfileCreated",
                    "requestMetadata": {"destinationAttributes": {}, "requestAttributes": {}},
                    "resourceName": "organizations/123456789012/inboundSsoSettings",
                    "serviceName": "admin.googleapis.com",
                },
                "receiveTimestamp": "2023-11-17T19:55:25.012649522Z",
                "resource": {
                    "labels": {
                        "method": "google.admin.AdminService.inboundSsoProfileCreated",
                        "service": "admin.googleapis.com",
                    },
                    "type": "audited_resource",
                },
                "severity": "NOTICE",
                "timestamp": "2023-11-17T19:55:24.521362Z",
            },
        ),
    ]
