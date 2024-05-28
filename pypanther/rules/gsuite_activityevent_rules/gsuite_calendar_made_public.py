from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

g_suite_calendar_made_public_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="User Publically Shared a Calendar",
        ExpectedResult=True,
        Log={
            "actor": {"email": "user@example.io", "profileId": "110111111111111111111"},
            "id": {
                "applicationName": "calendar",
                "customerId": "D12345",
                "time": "2022-12-10 22:33:31.852000000",
                "uniqueQualifier": "-2888888888888888888",
            },
            "ipAddress": "1.2.3.4",
            "kind": "admin#reports#activity",
            "name": "change_calendar_acls",
            "ownerDomain": "example.io",
            "parameters": {
                "access_level": "freebusy",
                "api_kind": "web",
                "calendar_id": "user@example.io",
                "grantee_email": "__public_principal__@public.calendar.google.com",
                "user_agent": "Mozilla/5.0",
            },
            "type": "calendar_change",
        },
    ),
    PantherRuleTest(
        Name="User Made Calendar Private",
        ExpectedResult=True,
        Log={
            "actor": {"email": "user@example.io", "profileId": "110111111111111111111"},
            "id": {
                "applicationName": "calendar",
                "customerId": "D12345",
                "time": "2022-12-10 22:33:31.852000000",
                "uniqueQualifier": "-2888888888888888888",
            },
            "ipAddress": "1.2.3.4",
            "kind": "admin#reports#activity",
            "name": "change_calendar_acls",
            "ownerDomain": "example.io",
            "parameters": {
                "access_level": "none",
                "api_kind": "web",
                "calendar_id": "user@example.io",
                "grantee_email": "__public_principal__@public.calendar.google.com",
                "user_agent": "Mozilla/5.0",
            },
            "type": "calendar_change",
        },
    ),
    PantherRuleTest(
        Name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_WRITE_ACCESS",
        ExpectedResult=False,
        Log={
            "actor": {"callerType": "USER", "email": "example@example.io", "profileId": "12345"},
            "id": {
                "applicationName": "admin",
                "customerId": "D12345",
                "time": "2022-12-11 01:06:26.303000000",
                "uniqueQualifier": "-12345",
            },
            "ipAddress": "12.12.12.12",
            "kind": "admin#reports#activity",
            "name": "CHANGE_CALENDAR_SETTING",
            "parameters": {
                "DOMAIN_NAME": "example.io",
                "NEW_VALUE": "READ_WRITE_ACCESS",
                "OLD_VALUE": "READ_ONLY_ACCESS",
                "ORG_UNIT_NAME": "Example IO",
                "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN",
            },
            "type": "CALENDAR_SETTINGS",
        },
    ),
    PantherRuleTest(
        Name="ListObject Type",
        ExpectedResult=False,
        Log={
            "actor": {"email": "user@example.io", "profileId": "118111111111111111111"},
            "id": {
                "applicationName": "drive",
                "customerId": "D12345",
                "time": "2022-12-20 17:27:47.080000000",
                "uniqueQualifier": "-7312729053723258069",
            },
            "ipAddress": "12.12.12.12",
            "kind": "admin#reports#activity",
            "name": "rename",
            "parameters": {
                "actor_is_collaborator_account": None,
                "billable": True,
                "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
                "doc_title": "Document Title- Found Here",
                "doc_type": "presentation",
                "is_encrypted": None,
                "new_value": ["Document Title- Found Here"],
                "old_value": ["Document Title- Old"],
                "owner": "user@example.io",
                "owner_is_shared_drive": None,
                "owner_is_team_drive": None,
                "primary_event": True,
                "visibility": "private",
            },
            "type": "access",
        },
    ),
]


class GSuiteCalendarMadePublic(PantherRule):
    RuleID = "GSuite.CalendarMadePublic-prototype"
    DisplayName = "GSuite Calendar Has Been Made Public"
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite"]
    Reports = {"MITRE ATT&CK": ["TA0007:T1087"]}
    Severity = PantherSeverity.Medium
    Description = "A User or Admin Has Modified A Calendar To Be Public\n"
    Reference = "https://support.google.com/calendar/answer/37083?hl=en&sjid=864417124752637253-EU"
    Runbook = "Follow up with user about this calendar share.\n"
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_calendar_made_public_tests

    def rule(self, event):
        return (
            event.get("name") == "change_calendar_acls"
            and event.get("parameters", {}).get("grantee_email")
            == "__public_principal__@public.calendar.google.com"
        )

    def title(self, event):
        return f"GSuite calendar [{deep_get(event, 'parameters', 'calendar_id', default='<NO_CALENDAR_ID>')}] made {self.public_or_private(event)} by [{deep_get(event, 'actor', 'email', default='<NO_ACTOR_FOUND>')}]"

    def severity(self, event):
        return "LOW" if self.public_or_private(event) == "private" else "MEDIUM"

    def public_or_private(self, event):
        return "private" if deep_get(event, "parameters", "access_level") == "none" else "public"
