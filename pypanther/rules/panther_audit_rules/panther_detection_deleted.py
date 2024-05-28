from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

panther_detection_deleted_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Delete 1 Detection",
        ExpectedResult=True,
        Log={
            "actionName": "DELETE_DETECTION",
            "actionParams": {
                "dynamic": {"input": {"detections": [{"id": "GitHub.Team.Modified"}]}}
            },
            "actionResult": "SUCCEEDED",
            "actor": {
                "attributes": {
                    "email": "homer@springfield.gov",
                    "emailVerified": True,
                    "roleId": "11111111",
                },
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
    PantherRuleTest(
        Name="Delete Many Detections",
        ExpectedResult=True,
        Log={
            "actionName": "DELETE_DETECTION",
            "actionParams": {
                "dynamic": {
                    "input": {
                        "detections": [
                            {"id": "Github.Repo.Created"},
                            {"id": "Okta.Global.MFA.Disabled"},
                            {"id": "Okta.AdminRoleAssigned"},
                            {"id": "Okta.BruteForceLogins"},
                        ]
                    }
                }
            },
            "actionResult": "SUCCEEDED",
            "actor": {
                "attributes": {
                    "email": "homer@springfield.gov",
                    "emailVerified": True,
                    "roleId": "111111",
                },
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
    PantherRuleTest(
        Name="Non-Delete event",
        ExpectedResult=False,
        Log={
            "actionName": "GET_GENERAL_SETTINGS",
            "actionParams": {},
            "actionResult": "SUCCEEDED",
            "actor": {
                "attributes": {
                    "email": "homer@springfield.gov",
                    "emailVerified": True,
                    "roleId": "111111",
                },
                "id": "111111",
                "name": "Homer Simpson",
                "type": "USER",
            },
            "errors": None,
            "p_log_type": "Panther.Audit",
        },
    ),
]


class PantherDetectionDeleted(PantherRule):
    RuleID = "Panther.Detection.Deleted-prototype"
    DisplayName = "Detection content has been deleted from Panther"
    LogTypes = [LogType.Panther_Audit]
    Severity = PantherSeverity.Info
    Tags = ["DataModel", "Defense Evasion:Impair Defenses"]
    Reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    Description = "Detection content has been removed from Panther."
    Runbook = "Ensure this change was approved and appropriate."
    Reference = "https://docs.panther.com/system-configuration/panther-audit-logs/querying-and-writing-detections-for-panther-audit-logs"
    SummaryAttributes = ["p_any_ip_addresses"]
    Tests = panther_detection_deleted_tests
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
            detections_list = deep_get(event, "actionParams", "input", "detections")
        return {
            "deleted_detections_list": [x.get("id") for x in detections_list],
            "user": event.udm("actor_user"),
            "ip": event.udm("source_ip"),
        }
