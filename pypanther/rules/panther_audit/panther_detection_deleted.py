from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

panther_detection_deleted_tests: list[RuleTest] = [
    RuleTest(
        name="Delete 1 Detection",
        expected_result=True,
        log={
            "actionName": "DELETE_DETECTION",
            "actionParams": {"dynamic": {"input": {"detections": [{"id": "GitHub.Team.Modified"}]}}},
            "actionResult": "SUCCEEDED",
            "actor": {
                "attributes": {"email": "homer@springfield.gov", "emailVerified": True, "roleId": "11111111"},
                "id": "1111111",
                "name": "Homer Simpson",
                "type": "USER",
            },
            "errors": None,
            "p_log_type": "Panther.Audit",
            "sourceIP": "1.2.3.4",
            "timestamp": "2022-04-28 15:30:22.42",
        },
    ),
    RuleTest(
        name="Delete Many Detections",
        expected_result=True,
        log={
            "actionName": "DELETE_DETECTION",
            "actionParams": {
                "dynamic": {
                    "input": {
                        "detections": [
                            {"id": "Github.Repo.Created"},
                            {"id": "Okta.Global.MFA.Disabled"},
                            {"id": "Okta.AdminRoleAssigned"},
                            {"id": "Okta.BruteForceLogins"},
                        ],
                    },
                },
            },
            "actionResult": "SUCCEEDED",
            "actor": {
                "attributes": {"email": "homer@springfield.gov", "emailVerified": True, "roleId": "111111"},
                "id": "1111111",
                "name": "Homer Simpson",
                "type": "USER",
            },
            "errors": None,
            "p_log_type": "Panther.Audit",
            "sourceIP": "1.2.3.4.",
            "timestamp": "2022-04-28 15:34:43.067",
        },
    ),
    RuleTest(
        name="Non-Delete event",
        expected_result=False,
        log={
            "actionName": "GET_GENERAL_SETTINGS",
            "actionParams": {},
            "actionResult": "SUCCEEDED",
            "actor": {
                "attributes": {"email": "homer@springfield.gov", "emailVerified": True, "roleId": "111111"},
                "id": "111111",
                "name": "Homer Simpson",
                "type": "USER",
            },
            "errors": None,
            "p_log_type": "Panther.Audit",
        },
    ),
]


@panther_managed
class PantherDetectionDeleted(Rule):
    id = "Panther.Detection.Deleted-prototype"
    display_name = "Detection content has been deleted from Panther"
    log_types = [LogType.PANTHER_AUDIT]
    default_severity = Severity.INFO
    tags = ["DataModel", "Defense Evasion:Impair Defenses"]
    reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    default_description = "Detection content has been removed from Panther."
    default_runbook = "Ensure this change was approved and appropriate."
    default_reference = "https://docs.panther.com/system-configuration/panther-audit-logs/querying-and-writing-detections-for-panther-audit-logs"
    summary_attributes = ["p_any_ip_addresses"]
    tests = panther_detection_deleted_tests
    PANTHER_DETECTION_DELETE_ACTIONS = [
        "DELETE_DATA_MODEL",
        "DELETE_DETECTION",
        "DELETE_DETECTION_PACK_SOURCE",
        "DELETE_GLOBAL_HELPER",
        "DELETE_LOOKUP_TABLE",
        "DELETE_SAVED_DATA_LAKE_QUERY",
    ]

    def rule(self, event):
        return (
            event.get("actionName") in self.PANTHER_DETECTION_DELETE_ACTIONS
            and event.get("actionResult") == "SUCCEEDED"
        )

    def title(self, event):
        return f"Detection Content has been deleted by {event.udm('actor_user')}"

    def alert_context(self, event):
        detections_list = deep_get(event, "actionParams", "dynamic", "input", "detections")
        if detections_list is None:
            detections_list = deep_get(event, "actionParams", "input", "detections", default=[])
        return {
            "deleted_detections_list": [x.get("id") for x in detections_list],
            "user": event.udm("actor_user"),
            "ip": event.udm("source_ip"),
        }
