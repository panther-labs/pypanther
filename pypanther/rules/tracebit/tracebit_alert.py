from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class TracebitAlert(Rule):
    id = "Tracebit.Alert-prototype"
    display_name = "Tracebit Alert"
    log_types = [LogType.TRACEBIT_ALERT]
    default_severity = Severity.MEDIUM
    default_description = "Tracebit maintains security canaries across your organization to detect potential intrusions.\n\nThis alert indicates that Tracebit has detected activity on security canaries."
    dedup_period_minutes = 1440

    def rule(self, event):
        return event.deep_get("discriminator", "type") == "tracebit_alert_log"

    def title(self, event):
        return f"Tracebit: {event.get('message')}"

    def dedup(self, event):
        # Deduplicate alerts on the alert_id since there can be multiple alert logs for a single alert
        return event.get("alert_id")

    def reference(self, event):
        # Reference the alert in the Tracebit portal to allow for easy investigation
        return event.get("tracebit_portal_url")

    def severity(self, event):
        # Override the default alert severity if the alert log has a high severity
        if event.get("severity") == "High":
            return "HIGH"
        return "DEFAULT"

    def alert_context(self, event):
        return event.get("canary", {})

    tests = [
        RuleTest(
            name="AWS Canary Accessed",
            expected_result=True,
            log={
                "alert_id": "62a3b514-50f2-4321-9117-73cab9690b15",
                "canary": {
                    "aws": {
                        "account_id": "613260573123",
                        "account_name": "companyx-prod",
                        "arn": "arn:aws:s3:::companyx-development-quarterly-monitor",
                    },
                    "name": "companyx-development-quarterly-monitor",
                    "provider_account_id": "613260573123",
                    "provider_id": "arn:aws:s3:::companyx-development-quarterly-monitor",
                    "tracebit_id": "00ee51db-fb6d-4f9f-8be8-f0db6004d9f0",
                    "type": "AWS::S3::Bucket",
                },
                "discriminator": {"subtype": "canary_resource_accessed", "type": "tracebit_alert_log"},
                "event": {
                    "id": "dfada3b1-5683-4a19-b392-7188a0ee8dbc",
                    "operation": "ListObjects",
                    "request": {
                        "ip": "212.36.35.20",
                        "user_agent": {
                            "label": "AWS Console",
                            "raw": "[S3Console/0.4, aws-internal/3 aws-sdk-java/1.12.750 Linux/5.10.223-190.873.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.412-b09 java/1.8.0_412 vendor/Oracle_Corporation cfg/retry-mode/standard]",
                        },
                    },
                    "resources": [
                        {"id": "companyx-development-quarterly-monitor", "type": "AWS::S3::Bucket"},
                        {"id": "companyx-development-quarterly-monitor/backup/", "type": "AWS::S3::Object"},
                    ],
                },
                "id": "dfada3b1-5683-4a19-b392-7188a0ee8dbc",
                "message": "Canary resource activity detected in AWS",
                "principal": {
                    "aws": {
                        "account_id": "613260573123",
                        "arn": "arn:aws:sts::613260573123:assumed-role/AWSReservedSSO_ExampleAdmin_8f33df3b277bcg12/john.smith@companyx.com",
                        "type": "AssumedRole",
                    },
                    "id": "AWSReservedSSO_ExampleAdmin_8f33df3b277bcg12/john.smith@companyx.com",
                },
                "provider": "aws",
                "severity": "Medium",
                "timestamp": "2024-09-04T08:06:28Z",
                "tracebit_portal_url": "https://companyx.tracebit.com/alerts/62a3b514-50f2-4321-9117-73cab9690b15",
            },
        ),
        RuleTest(
            name="AWS Canary Credential Used",
            expected_result=True,
            log={
                "alert_id": "fba46ed3-a454-4e85-a71a-9a89a257b150",
                "canary_credential": {
                    "aws": {"access_key_id": "ASIAWMAFDUWHGG4P5FYU"},
                    "expires_at": "2024-09-05T03:08:17Z",
                    "issued_at": "2024-09-03T15:08:17.513903Z",
                    "labels": [{"name": "source", "value": "kandji"}, {"name": "source_type", "value": "endpoint"}],
                    "name": "john.smith@us-sf01-596",
                    "type": "aws_temporary_security_credentials",
                },
                "discriminator": {"subtype": "canary_credential_used", "type": "tracebit_alert_log"},
                "event": {
                    "id": "4f83e279-96fa-4ebd-80e6-ec3ea89d7375",
                    "operation": "GetCallerIdentity",
                    "request": {
                        "ip": "212.36.35.20",
                        "user_agent": {
                            "label": "AWS CLI",
                            "raw": "aws-cli/2.15.42 Python/3.11.8 Darwin/23.5.0 exe/x86_64 prompt/off command/sts.get-caller-identity",
                        },
                    },
                    "resources": [],
                },
                "id": "4f83e279-96fa-4ebd-80e6-ec3ea89d7375",
                "message": "Canary AWS credentials used",
                "principal": {
                    "aws": {
                        "account_id": "519571432283",
                        "arn": "arn:aws:sts::519571432283:federated-user/15a1cfdf4eee48d78d9as66446dbcf43",
                        "type": "FederatedUser",
                    },
                    "id": "519571432283:15a1cfdf4eee48d78d9as66446dbcf43",
                },
                "provider": "aws",
                "severity": "High",
                "timestamp": "2024-09-03T15:49:28Z",
                "tracebit_portal_url": "https://companyx.tracebit.com/alerts/fba46ed3-a454-4e85-a71a-9a89a257b150",
            },
        ),
        RuleTest(
            name="Azure Canary Accessed",
            expected_result=True,
            log={
                "alert_id": "700f8618-69ee-4364-9ae5-1f6b73ca9319",
                "canary": {
                    "azure": {
                        "resource_id": "/subscriptions/8d4d189a-fb4a-4075-b382-fd470afac0e8/resourceGroups/windows-rg/providers/Microsoft.Storage/storageAccounts/prodwindowsvmbackups002",
                        "subscription_id": "8d4d189a-fb4a-4075-b382-fd470afac0e8",
                        "subscription_name": "prod-windows-env",
                    },
                    "name": "prodwindowsvmbackups002",
                    "provider_account_id": "8d4d189a-fb4a-4075-b382-fd470afac0e8",
                    "provider_id": "/subscriptions/8d4d189a-fb4a-4075-b382-fd470afac0e8/resourceGroups/windows-rg/providers/Microsoft.Storage/storageAccounts/prodwindowsvmbackups002",
                    "tracebit_id": "20f68e26-5536-4d3a-be75-9e025995fde3",
                    "type": "Azure::Microsoft.Storage::storageAccounts",
                },
                "discriminator": {"subtype": "canary_resource_accessed", "type": "tracebit_alert_log"},
                "event": {
                    "id": "c85e7157-8c09-4c01-a86a-b5a5a93d190d",
                    "operation": "ListBlobs",
                    "request": {
                        "ip": "212.36.35.20",
                        "user_agent": {
                            "label": "Chrome 128.0.0, Mac OS X 10.15.7, Mac",
                            "raw": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                        },
                    },
                    "resources": [
                        {"id": "prodwindowsvmbackups002", "type": "Azure::Microsoft.Storage::storageAccounts"},
                    ],
                },
                "id": "c85e7157-8c09-4c01-a86a-b5a5a93d190d",
                "message": "Canary resource activity detected in Azure",
                "principal": {
                    "azure": {
                        "app_id": "3acc04f1-3423-4960-8c19-6888bcf03bd6",
                        "tenant_id": "41d2d53a-215c-4c7c-9ff6-617900062eec",
                    },
                    "id": "e84f519e-df08-47d8-b580-b4caf7571b98",
                },
                "provider": "azure",
                "severity": "Medium",
                "timestamp": "2024-09-03T15:04:48.836334Z",
                "tracebit_portal_url": "https://companyx.tracebit.com/alerts/700f8618-69ee-4364-9ae5-1f6b73ca9319",
            },
        ),
        RuleTest(
            name="Okta Canary Accessed",
            expected_result=True,
            log={
                "alert_id": "ad35c8b8-9b01-4e96-ab19-61647beead7e",
                "canary": {
                    "name": "Audit Logs",
                    "okta": {"domain": "companyx.okta.com", "organization_id": "00oh4kb5sgKSgaej53d7"},
                    "provider_account_id": "00oh4kb5sgKSgaej53d7",
                    "provider_id": "0oaj43kdk9unmg8Dk3d7",
                    "tracebit_id": "43a24f5a-21fb-4680-9ce4-27fb10448f9a",
                    "type": "Okta::App",
                },
                "discriminator": {"subtype": "canary_resource_accessed", "type": "tracebit_alert_log"},
                "event": {
                    "id": "f69f2428-6a05-11ef-b0d9-d9d6ee4e8e7e",
                    "operation": "policy.evaluate_sign_on",
                    "request": {
                        "ip": "212.36.35.20",
                        "user_agent": {
                            "label": "Mac OS X (CHROME)",
                            "raw": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                        },
                    },
                    "resources": [
                        {"id": "Audit Logs", "type": "AppInstance"},
                        {"id": "Catch-all Rule", "type": "Rule"},
                    ],
                },
                "id": "f69f2428-6a05-11ef-b0d9-d9d6ee4e8e7e",
                "message": "Canary resource activity detected in Okta",
                "principal": {
                    "id": "00uh1dk4sdgbtSkM23d7",
                    "okta": {
                        "alternate_id": "john.smith+user@companyx.com",
                        "id": "00uh1dk4sdgbtSkM23d7",
                        "type": "User",
                    },
                },
                "provider": "okta",
                "severity": "High",
                "timestamp": "2024-09-03T15:05:31.678Z",
                "tracebit_portal_url": "https://companyx.tracebit.com/alerts/ad35c8b8-9b01-4e96-ab19-61647beead7e",
            },
        ),
    ]
