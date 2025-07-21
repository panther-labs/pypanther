from panther_core import PantherEvent

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GoogleWorkspaceManyDocsDownloaded(Rule):
    id = "Google.Workspace.ManyDocsDownloaded-prototype"
    display_name = "Google Workspace Many Docs Downloaded"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    default_severity = Severity.INFO
    create_alert = False
    reports = {"MITRE ATT&CK": ["TA0010:T1567"]}
    default_description = (
        "Checks whether a user has downloaded a large number of documents from Google Drive within a 5-minute period.\n"
    )
    dedup_period_minutes = 5
    threshold = 20
    default_reference = "https://support.google.com/drive/answer/2423534?hl=en&co=GENIE.Platform%3DDesktop\n"
    summary_attributes = ["p_any_usernames", "parameters:doc_title"]
    tags = ["GSuite ActivityEvent", "Beta"]

    def rule(self, event: PantherEvent) -> bool:
        return event.get("name") == "download"

    def alert_context(self, event: PantherEvent) -> dict:
        return {
            "actor": event.deep_get("actor", "email", default="<UNKNOWN ACTOR>"),
            "document_name": event.deep_get("parameters", "doc_title", default="<UNKNOWN DOCUMENT>"),
        }

    tests = [
        RuleTest(
            name="Document Downloaded",
            expected_result=True,
            log={
                "actor": {"email": "wiley.coyote@acme.com", "profileId": "112233445566778899001"},
                "id": {
                    "applicationName": "drive",
                    "customerId": "CUSTID",
                    "time": "2025-03-21 21:29:49.364000000",
                    "uniqueQualifier": "-1234567891234567890",
                },
                "ipAddress": "1.1.1.1",
                "kind": "admin#reports#activity",
                "name": "download",
                "parameters": {
                    "billable": True,
                    "doc_id": "123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ0-a1B2c3D",
                    "doc_title": "My Sensitive Document",
                    "doc_type": "spreadsheet",
                    "owner": "HR",
                    "owner_is_shared_drive": True,
                    "owner_is_team_drive": True,
                    "owner_team_drive_id": "123456789aB_a1B2c3D",
                    "primary_event": True,
                    "shared_drive_id": "123456789aB_a1B2c3D",
                    "team_drive_id": "123456789aB_a1B2c3D",
                    "visibility": "shared_internally",
                },
                "type": "access",
            },
        ),
        RuleTest(
            name="Document Viewed",
            expected_result=False,
            log={
                "actor": {"email": "wiley.coyote@acme.com", "profileId": "112233445566778899001"},
                "id": {
                    "applicationName": "drive",
                    "customerId": "CUSTID",
                    "time": "2025-03-21 21:29:49.364000000",
                    "uniqueQualifier": "-1234567891234567890",
                },
                "ipAddress": "1.1.1.1",
                "kind": "admin#reports#activity",
                "name": "view",
                "parameters": {
                    "billable": True,
                    "doc_id": "123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ0-a1B2c3D",
                    "doc_title": "My Sensitive Document",
                    "doc_type": "spreadsheet",
                    "owner": "HR",
                    "owner_is_shared_drive": True,
                    "owner_is_team_drive": True,
                    "owner_team_drive_id": "123456789aB_a1B2c3D",
                    "primary_event": True,
                    "shared_drive_id": "123456789aB_a1B2c3D",
                    "team_drive_id": "123456789aB_a1B2c3D",
                    "visibility": "shared_internally",
                },
                "type": "access",
            },
        ),
    ]
