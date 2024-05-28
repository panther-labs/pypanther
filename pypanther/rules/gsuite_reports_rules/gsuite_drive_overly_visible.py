from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_base_helpers import gsuite_details_lookup as details_lookup
from pypanther.helpers.panther_base_helpers import gsuite_parameter_lookup as param_lookup
from pypanther.log_types import LogType

g_suite_drive_overly_visible_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Access Event",
        ExpectedResult=False,
        Log={
            "p_row_id": "111222",
            "actor": {"email": "bobert@example.com"},
            "id": {"applicationName": "drive"},
            "events": [{"type": "access", "name": "download"}],
        },
    ),
    PantherRuleTest(
        Name="Modify Event Without Over Visibility",
        ExpectedResult=False,
        Log={
            "p_row_id": "111222",
            "actor": {"email": "bobert@example.com"},
            "id": {"applicationName": "drive"},
            "events": [
                {
                    "type": "access",
                    "name": "edit",
                    "parameters": [{"name": "visibility", "value": "private"}],
                }
            ],
        },
    ),
    PantherRuleTest(
        Name="Overly Visible Doc Modified",
        ExpectedResult=True,
        Log={
            "p_row_id": "111222",
            "actor": {"email": "bobert@example.com"},
            "id": {"applicationName": "drive"},
            "events": [
                {
                    "type": "access",
                    "name": "edit",
                    "parameters": [
                        {"name": "visibility", "value": "people_with_link"},
                        {"name": "doc_title", "value": "my shared document"},
                    ],
                }
            ],
        },
    ),
    PantherRuleTest(
        Name="Overly Visible Doc Modified - no email",
        ExpectedResult=True,
        Log={
            "p_row_id": "111222",
            "actor": {"profileId": "1234567890123"},
            "id": {"applicationName": "drive"},
            "events": [
                {
                    "type": "access",
                    "name": "edit",
                    "parameters": [
                        {"name": "visibility", "value": "people_with_link"},
                        {"name": "doc_title", "value": "my shared document"},
                    ],
                }
            ],
        },
    ),
]


class GSuiteDriveOverlyVisible(PantherRule):
    RuleID = "GSuite.DriveOverlyVisible-prototype"
    DisplayName = "GSuite Overly Visible Drive Document"
    LogTypes = [LogType.GSuite_Reports]
    Tags = ["GSuite", "Collection:Data from Information Repositories"]
    Reports = {"MITRE ATT&CK": ["TA0009:T1213"]}
    Severity = PantherSeverity.Info
    Description = "A Google drive resource that is overly visible has been modified.\n"
    Reference = "https://support.google.com/docs/answer/2494822?hl=en&co=GENIE.Platform%3DDesktop&sjid=864417124752637253-EU"
    Runbook = "Investigate whether the drive document is appropriate to be this visible.\n"
    SummaryAttributes = ["actor:email"]
    DedupPeriodMinutes = 360
    Tests = g_suite_drive_overly_visible_tests
    RESOURCE_CHANGE_EVENTS = {"create", "move", "upload", "edit"}
    PERMISSIVE_VISIBILITY = {"people_with_link", "public_on_the_web"}

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "drive":
            return False
        details = details_lookup("access", self.RESOURCE_CHANGE_EVENTS, event)
        return (
            bool(details)
            and param_lookup(details.get("parameters", {}), "visibility")
            in self.PERMISSIVE_VISIBILITY
        )

    def dedup(self, event):
        user = deep_get(event, "actor", "email")
        if user is None:
            user = deep_get(event, "actor", "profileId", default="<UNKNOWN_PROFILEID>")
        return user

    def title(self, event):
        details = details_lookup("access", self.RESOURCE_CHANGE_EVENTS, event)
        doc_title = param_lookup(details.get("parameters", {}), "doc_title")
        share_settings = param_lookup(details.get("parameters", {}), "visibility")
        user = deep_get(event, "actor", "email")
        if user is None:
            user = deep_get(event, "actor", "profileId", default="<UNKNOWN_PROFILEID>")
        return f"User [{user}] modified a document [{doc_title}] that has overly permissive share settings [{share_settings}]"
