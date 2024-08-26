from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_base_helpers import gsuite_details_lookup as details_lookup
from pypanther.helpers.panther_base_helpers import gsuite_parameter_lookup as param_lookup

g_suite_drive_overly_visible_tests: list[RuleTest] = [
    RuleTest(
        name="Access Event",
        expected_result=False,
        log={
            "p_row_id": "111222",
            "actor": {"email": "bobert@example.com"},
            "id": {"applicationName": "drive"},
            "events": [{"type": "access", "name": "download"}],
        },
    ),
    RuleTest(
        name="Modify Event Without Over Visibility",
        expected_result=False,
        log={
            "p_row_id": "111222",
            "actor": {"email": "bobert@example.com"},
            "id": {"applicationName": "drive"},
            "events": [{"type": "access", "name": "edit", "parameters": [{"name": "visibility", "value": "private"}]}],
        },
    ),
    RuleTest(
        name="Overly Visible Doc Modified",
        expected_result=True,
        log={
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
                },
            ],
        },
    ),
    RuleTest(
        name="Overly Visible Doc Modified - no email",
        expected_result=True,
        log={
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
                },
            ],
        },
    ),
]


@panther_managed
class GSuiteDriveOverlyVisible(Rule):
    id = "GSuite.DriveOverlyVisible-prototype"
    display_name = "GSuite Overly Visible Drive Document"
    log_types = [LogType.GSUITE_REPORTS]
    tags = ["GSuite", "Collection:Data from Information Repositories"]
    reports = {"MITRE ATT&CK": ["TA0009:T1213"]}
    default_severity = Severity.INFO
    default_description = "A Google drive resource that is overly visible has been modified.\n"
    default_reference = (
        "https://support.google.com/docs/answer/2494822?hl=en&co=GENIE.Platform%3DDesktop&sjid=864417124752637253-EU"
    )
    default_runbook = "Investigate whether the drive document is appropriate to be this visible.\n"
    summary_attributes = ["actor:email"]
    dedup_period_minutes = 360
    tests = g_suite_drive_overly_visible_tests
    RESOURCE_CHANGE_EVENTS = {"create", "move", "upload", "edit"}
    PERMISSIVE_VISIBILITY = {"people_with_link", "public_on_the_web"}

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "drive":
            return False
        details = details_lookup("access", self.RESOURCE_CHANGE_EVENTS, event)
        return bool(details) and param_lookup(details.get("parameters", {}), "visibility") in self.PERMISSIVE_VISIBILITY

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
