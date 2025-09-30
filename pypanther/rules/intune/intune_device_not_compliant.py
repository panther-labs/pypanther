from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class IntuneDeviceNotCompliant(Rule):
    id = "Intune.DeviceNotCompliant-prototype"
    display_name = "Intune Device Not Compliant"
    log_types = [LogType.MICROSOFT_INTUNE_OPERATIONAL_LOGS]
    tags = ["InTune"]
    default_severity = Severity.LOW
    reports = {"MITRE ATT&CK": ["TA0005:T1652"]}
    default_description = "Microsoft Intune allows administrators to manage devices and enforce compliance with established policies. This detection identifies devices that are not compliant with the established policies."
    default_runbook = "Review the Description field for information about the policy that the device is not compliant with. This is typically easier to review and investigate in the Intune portal."
    default_reference = "https://learn.microsoft.com/en-us/intune/intune-service/protect/compliance-policy-monitor"
    HOSTNAME = ""

    def rule(self, event):
        return all(
            [
                event.get("operationName", "").lower() == "compliance",
                event.deep_get("properties", "AlertType", default="").lower() == "managed device not compliant",
            ],
        )

    def title(self, event):
        # Simple title with hostname of the non-compliant device
        self.HOSTNAME = event.deep_get("properties", "DeviceHostName", default="Unknown")
        return f"INTUNE: [{self.HOSTNAME}] reported as non-compliant"

    def alert_context(self, event):
        return {
            "Hostname": self.HOSTNAME,
            "Operating System": event.deep_get("properties", "DeviceOperatingSystem", default="Unknown"),
            "User": event.deep_get("properties", "UserName", default="Unknown"),
            "User Display Name": event.deep_get("properties", "UserDisplayName", default="Unknown"),
            "Description": event.deep_get("properties", "Description", default="Unknown"),
        }

    tests = [
        RuleTest(
            name="Device Reported Not Compliant",
            expected_result=True,
            log={
                "category": "OperationalLogs",
                "operationName": "Compliance",
                "properties": {
                    "AADTenantId": "11111111-2222-3333-4444-555555555555",
                    "AlertDisplayName": "Managed Device TestDevice_8/2/2024_6:32 PM is not Compliant",
                    "AlertType": "Managed Device Not Compliant",
                    "Description": "DefaultDeviceCompliancePolicy.RequireRemainContact||DefaultDeviceCompliancePolicy.RequireRemainContact||DefaultDeviceCompliancePolicy.RequireRemainContact||Expected recent contact. Last contact: 2025-03-27 17:35:40Z||2025-03-27 17:35:40Z||ComplianceCalculation",
                    "DeviceDnsDomain": "",
                    "DeviceHostName": "TestDevice",
                    "DeviceName": "TestDevice_8/2/2024_6:32 PM",
                    "DeviceNetBiosName": "TestDevice",
                    "DeviceOperatingSystem": "Windows 10.0.26100.2894",
                    "IntuneAccountId": "11111111-2222-3333-4444-555555555555",
                    "IntuneDeviceId": "11111111-2222-3333-4444-555555555555",
                    "IntuneUserId": "11111111-2222-3333-4444-555555555555",
                    "OperationalLogCategory": "DeviceCompliance",
                    "ScaleUnit": "AMSUA0602",
                    "ScenarioName": "Microsoft.Management.Services.Diagnostics.SLAEvents.DeviceNotInComplianceSecurityAlert",
                    "StartTimeUtc": "2025-04-02T05:57:59.4097Z",
                    "UPNSuffix": "test.com",
                    "UserDisplayName": "Device Enrollment Manager",
                    "UserName": "testuser",
                },
                "resultType": "None",
                "tenantId": "11111111-2222-3333-4444-555555555555",
                "time": "2025-04-02T05:57:59.4097000Z",
            },
        ),
        RuleTest(
            name="Device Enrollment",
            expected_result=False,
            log={
                "category": "OperationalLogs",
                "operationName": "Enrollment",
                "properties": {
                    "AADDeviceId": "11111111-2222-3333-4444-555555555555",
                    "AADTenantId": "11111111-2222-3333-4444-555555555555",
                    "EnrollmentTimeUTC": "2025-04-09T15:59:08.5840Z",
                    "EnrollmentType": "WindowsAzureADJoin",
                    "FailureCategory": "Not Applicable",
                    "FailureReason": "Unknown",
                    "IntuneAccountId": "11111111-2222-3333-4444-555555555555",
                    "IntuneDeviceId": "11111111-2222-3333-4444-555555555555",
                    "IntuneUserId": "11111111-2222-3333-4444-555555555555",
                    "MessageId": "11111111-2222-3333-4444-555555555555",
                    "OperationalLogCategory": "DeviceEnrollment",
                    "Os": "Windows",
                    "OsVersion": "10.0.26100.1742",
                    "ScaleUnit": "AMSUA0602",
                    "ScenarioName": "Microsoft.Management.Services.Diagnostics.SLAEvents.EnrollmentSLAEvent",
                },
                "resultType": "Success",
                "tenantId": "11111111-2222-3333-4444-555555555555",
                "time": "2025-04-09T15:59:08.5840000Z",
            },
        ),
    ]
