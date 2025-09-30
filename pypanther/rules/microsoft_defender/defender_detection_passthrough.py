from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class DefenderDetectionpassthrough(Rule):
    id = "Defender.Detection.passthrough-prototype"
    display_name = "Defender Detection Passthrough"
    log_types = [LogType.MICROSOFT_DEFENDER_X_D_R_ADVANCED_HUNTING]
    tags = ["Defender"]
    default_severity = Severity.MEDIUM
    default_description = "Microsoft Defender has detected malicious activity. This activty could be on a host or on a connected platform such as Azure, Microsoft 365, or Intune."
    default_runbook = "."
    default_reference = "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table"
    ALERT_URL = ""

    def rule(self, event):
        # Alert on any AlertInfo event
        return event.get("category") == "AdvancedHunting-AlertInfo"

    def title(self, event):
        # Simple title with the native Defender alert title
        return f"Defender Alert: [{event.deep_get('properties', 'Title', default='Unknown')}]"

    def alert_context(self, event):
        # Use the AlertId and tenantId to generate a URL to the alert in the Microsoft 365 Security
        # Center. The tenant ID is not completely necessary, but is helpful if a user is a member
        # of multiple tenants
        alert_id = event.deep_get("properties", "AlertId", default="Unknown")
        tenant_id = event.deep_get("tenantId", default="Unknown")
        if alert_id != "Unknown" and tenant_id != "Unknown":
            self.ALERT_URL = f"https://security.microsoft.com/alerts/{alert_id}?tid={tenant_id}"
        else:
            self.ALERT_URL = ""
        return {
            "AlertId": alert_id,
            "Name": event.deep_get("properties", "Title", default="Unknown"),
            "Severity": event.deep_get("properties", "Severity", default="Unknown"),
            "Source": event.deep_get("properties", "DetectionSource", default="Unknown"),
            "ATT&CK Techniques": event.deep_get("properties", "AttackTechniques", default="Unknown"),
            "Alert URL": self.ALERT_URL,
        }

    def reference(self, _):
        # If the alert ID is not found, return the Microsoft Defender documentation for the
        # AlertInfo table.
        if self.ALERT_URL:
            return self.ALERT_URL
        return "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table"

    def severity(self, event):
        return event.deep_get("properties", "Severity", default="MEDIUM")

    def dedup(self, event):
        return f"{event.deep_get('properties', 'AlertId', default='Unknown')} "

    tests = [
        RuleTest(
            name="High Severity Finding",
            expected_result=True,
            log={
                "_TimeReceivedBySvc": "2025-04-11 21:07:42.726000000",
                "category": "AdvancedHunting-AlertInfo",
                "operationName": "Publish",
                "properties": {
                    "AlertId": "0000000000-1111-2222-3333-444444444444",
                    "AttackTechniques": '["System Binary Proxy Execution (T1218)","Regsvr32 (T1218.010)","Rundll32 (T1218.011)"]',
                    "Category": "DefenseEvasion",
                    "DetectionSource": "Scheduled Alerts",
                    "ServiceSource": "Microsoft Sentinel",
                    "Severity": "High",
                    "Timestamp": "2025-04-21 20:51:04.058183200",
                    "Title": "Regsvr32 Rundll32 Image Loads Abnormal Extension",
                },
                "Tenant": "DefaultTenant",
                "tenantId": "55555555-6666-7777-8888-999999999999",
                "time": "2025-04-11 21:07:42.781656600",
            },
        ),
        RuleTest(
            name="Alert Evidence Event",
            expected_result=False,
            log={
                "_TimeReceivedBySvc": "2025-04-11 21:07:42.759000000",
                "category": "AdvancedHunting-AlertEvidence",
                "operationName": "Publish",
                "properties": {
                    "AdditionalFields": '{"DnsDomain":"test.com","HostName":"testdevice","NetBiosName":"testdevice.testdomain.com","IsDomainJoined":true,"RbacScopes":{"ScopesPerType":{"Workloads":{"Mode":"All","Scopes":["Sentinel"]},"Workspace":{"Mode":"All","Scopes":["82f5e56e-5ba9-421a-9556-03a95490c2a7"]}}},"Type":"host","MachineId":"0123456789abcdef0123456789abcdef","MachineIdType":3,"Role":0,"MergeByKey":"x/NzTINVL5AfAzJZ5aSiYJOW9uQ=","MergeByKeyHex":"C7F3734C83552F901F033259E5A4A2609396F6E4"}',
                    "AlertId": "sn34c87846-505a-4c84-b125-44bce1202df4",
                    "AttackTechniques": '["System Binary Proxy Execution (T1218)","Regsvr32 (T1218.010)","Rundll32 (T1218.011)"]',
                    "Categories": '["DefenseEvasion"]',
                    "CloudPlatform": "",
                    "DetectionSource": "Scheduled Alerts",
                    "DeviceId": "0123456789abcdef0123456789abcdef",
                    "DeviceName": "testdevice.testdomain.com",
                    "EntityType": "Machine",
                    "EvidenceRole": "Impacted",
                    "ServiceSource": "Microsoft Sentinel",
                    "Severity": "High",
                    "SubscriptionId": "",
                    "Timestamp": "2025-04-11 20:51:04.058183200",
                    "Title": "Regsvr32 Rundll32 Image Loads Abnormal Extension",
                },
                "Tenant": "DefaultTenant",
                "tenantId": "2008f78a-ebba-4182-8f80-7d9a0aec27a5",
                "time": "2025-04-11 21:07:42.781258000",
            },
        ),
    ]
