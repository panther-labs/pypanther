from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.base import key_value_list_to_dict


@panther_managed
class GCPUserAddedToPrivilegedGroup(Rule):
    id = "GCP.User.Added.To.Privileged.Group-prototype"
    display_name = "GCP User Added to Privileged Group"
    enabled = False
    log_types = [LogType.GCP_AUDIT_LOG]
    default_severity = Severity.LOW
    tags = ["Configuration Required"]
    reports = {"MITRE ATT&CK": ["TA0004:T1078.004", "TA0004:T1484.001"]}
    default_description = "A user was added to a group with special previleges"
    default_reference = "https://github.com/GoogleCloudPlatform/security-analytics/blob/main/src/2.02/2.02.md"
    default_runbook = "Determine if the user had been added to the group for legitimate reasons."
    # "admins@example.com"
    PRIVILEGED_GROUPS = {}
    USER_EMAIL = ""
    GROUP_EMAIL = ""

    def rule(self, event):
        events = event.deep_get("protoPayload", "metadata", "event", default=[])
        for event_ in events:
            if event_.get("eventname") != "ADD_GROUP_MEMBER":
                continue
            # Get the username
            params = key_value_list_to_dict(event_.get("parameter", []), "name", "value")
            self.USER_EMAIL = params.get("USER_EMAIL")
            self.GROUP_EMAIL = params.get("GROUP_EMAIL")
            if self.GROUP_EMAIL in self.get_privileged_groups():
                return True
        return False

    def title(self, event):
        actor = event.deep_get("actor", "email", default="")
        return f"{actor} has added {self.USER_EMAIL} to the privileged group {self.GROUP_EMAIL}"

    def get_privileged_groups(self):
        # We make this a function, so we can mock it for unit tests
        return self.PRIVILEGED_GROUPS

    tests = [
        RuleTest(
            name="User Added to Privileged Group",
            expected_result=True,
            mocks=[RuleMock(object_name="get_privileged_groups", return_value='["admins@example.com"]')],
            log={
                "logName": "organizations/123/logs/cloudaudit.googleapis.com%2Factivity",
                "severity": "NOTICE",
                "insertId": "285djodxlmu",
                "resource": {
                    "type": "audited_resource",
                    "labels": {"method": "google.admin.AdminService.addGroupMember", "service": "admin.googleapis.com"},
                },
                "timestamp": "2022-03-22T22:12:58.916Z",
                "receiveTimestamp": "2022-03-22T22:12:59.439766009Z",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "admin.googleapis.com",
                    "methodName": "google.admin.AdminService.addGroupMember",
                    "resourceName": "organizations/123/groupSettings",
                    "authenticationInfo": {"principalEmail": "admin@example.com"},
                    "requestMetadata": {
                        "callerIP": "11.22.33.44",
                        "requestAttributes": {},
                        "destinationAttributes": {},
                    },
                    "metadata": {
                        "@type": "type.googleapis.com/ccc_hosted_reporting.ActivityProto",
                        "activityId": {"timeUsec": "1647987178916000", "uniqQualifier": "-8614641986436885296"},
                        "event": [
                            {
                                "eventName": "ADD_GROUP_MEMBER",
                                "eventType": "GROUP_SETTINGS",
                                "parameter": [
                                    {
                                        "label": "LABEL_OPTIONAL",
                                        "value": "test-user@example.com",
                                        "type": "TYPE_STRING",
                                        "name": "USER_EMAIL",
                                    },
                                    {
                                        "type": "TYPE_STRING",
                                        "value": "admins@example.com",
                                        "label": "LABEL_OPTIONAL",
                                        "name": "GROUP_EMAIL",
                                    },
                                ],
                            },
                        ],
                    },
                },
            },
        ),
        RuleTest(
            name="User Added to Non-Privileged Group",
            expected_result=False,
            log={
                "logName": "organizations/123/logs/cloudaudit.googleapis.com%2Factivity",
                "severity": "NOTICE",
                "insertId": "285djodxlmu",
                "resource": {
                    "type": "audited_resource",
                    "labels": {"method": "google.admin.AdminService.addGroupMember", "service": "admin.googleapis.com"},
                },
                "timestamp": "2022-03-22T22:12:58.916Z",
                "receiveTimestamp": "2022-03-22T22:12:59.439766009Z",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "admin.googleapis.com",
                    "methodName": "google.admin.AdminService.addGroupMember",
                    "resourceName": "organizations/123/groupSettings",
                    "authenticationInfo": {"principalEmail": "admin@example.com"},
                    "requestMetadata": {
                        "callerIP": "11.22.33.44",
                        "requestAttributes": {},
                        "destinationAttributes": {},
                    },
                    "metadata": {
                        "@type": "type.googleapis.com/ccc_hosted_reporting.ActivityProto",
                        "activityId": {"timeUsec": "1647987178916000", "uniqQualifier": "-8614641986436885296"},
                        "event": [
                            {
                                "eventName": "ADD_GROUP_MEMBER",
                                "eventType": "GROUP_SETTINGS",
                                "parameter": [
                                    {
                                        "label": "LABEL_OPTIONAL",
                                        "value": "test-user@example.com",
                                        "type": "TYPE_STRING",
                                        "name": "USER_EMAIL",
                                    },
                                    {
                                        "type": "TYPE_STRING",
                                        "value": "normies@example.com",
                                        "label": "LABEL_OPTIONAL",
                                        "name": "GROUP_EMAIL",
                                    },
                                ],
                            },
                        ],
                    },
                },
            },
        ),
    ]
