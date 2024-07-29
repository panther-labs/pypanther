from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

carbon_black_audit_data_forwarder_stopped_tests: list[RuleTest] = [
    RuleTest(
        name="Endpoint event forwarder disabled",
        expected_result=True,
        log={
            "clientIp": "12.34.56.78",
            "description": 'Updated Config: {"id":"b6ab1fb9-61f6-11ee-9e9b-5655adf4bf96","org_key":"A1234567","name":"endpoint event","enabled":false,"s3_bucket_name":"carbonblackbucket","s3_prefix":"endpoint","type":"endpoint.event","create_time":"2023-10-03T14:11:14Z","update_time":"2023-11-14T19:16:43Z"}\n',
            "eventId": "58bef441832211ee83ef1721d866b8d6",
            "eventTime": "2023-11-14 19:16:43.123000000",
            "flagged": False,
            "loginName": "bob.ross@acme.com",
            "orgName": "bob.ross@acme.com",
            "requestUrl": "/data_forwarder/v2/orgs/A1234567/configs/b6ab1fb9-61f6-11ee-9e9b-5655adf4bf96",
            "verbose": False,
        },
    ),
    RuleTest(
        name="Endpoint event forwarder updated",
        expected_result=False,
        log={
            "clientIp": "12.34.56.78",
            "description": 'Updated Config: {"id":"b6ab1fb9-61f6-11ee-9e9b-5655adf4bf96","org_key":"A1234567","name":"endpoint event","enabled":true,"s3_bucket_name":"carbonblackbucket","s3_prefix":"endpoint","type":"endpoint.event","create_time":"2023-10-03T14:11:14Z","update_time":"2023-11-14T19:16:43Z"}\n',
            "eventId": "58bef441832211ee83ef1721d866b8d6",
            "eventTime": "2023-11-14 19:16:43.123000000",
            "flagged": False,
            "loginName": "bob.ross@acme.com",
            "orgName": "bob.ross@acme.com",
            "requestUrl": "/data_forwarder/v2/orgs/A1234567/configs/b6ab1fb9-61f6-11ee-9e9b-5655adf4bf96",
            "verbose": False,
        },
    ),
]


@panther_managed
class CarbonBlackAuditDataForwarderStopped(Rule):
    id = "CarbonBlack.Audit.Data.Forwarder.Stopped-prototype"
    log_types = [LogType.CARBON_BLACK_AUDIT]
    default_description = "Detects when a user disables or deletes a Data Forwarder."
    display_name = "Carbon Black Data Forwarder Stopped"
    default_severity = Severity.HIGH
    tags = ["Defense Evasion", "Impair Defenses", "Disable or Modify Cloud Logs"]
    reports = {"MITRE ATT&CK": ["TA0005:T1562.008"]}
    default_reference = "https://docs.vmware.com/en/VMware-Carbon-Black-Cloud/services/carbon-black-cloud-user-guide/GUID-E8D33F72-BABB-4157-A908-D8BBDB5AF349.html"
    tests = carbon_black_audit_data_forwarder_stopped_tests
    ACTION = ""

    def rule(self, event):
        if not event.get("requestUrl", "").startswith("/data_forwarder/"):
            return False
        desc = event.get("description", "")
        if desc.startswith("Deleted Config: "):
            self.ACTION = "Deleted"
            return True
        if desc.startswith("Updated Config: ") and '"enabled":false' in desc:
            self.ACTION = "Disabled"
            return True
        return False

    def title(self, event):
        user = event.get("loginName", "<NO_USERNAME_FOUND>")
        ip_addr = event.get("clientIp", "<NO_IP_FOUND>")
        return f"{user} [{ip_addr}] {self.ACTION} Data Forwarder"

    def description(self, event):
        user = event.get("loginName")
        ip_addr = event.get("clientIp")
        desc = event.get("description")
        return f"{user} [{ip_addr}] {desc}"
