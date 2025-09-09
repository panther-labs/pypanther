from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GSuiteDocOwnershipTransfer(Rule):
    id = "GSuite.DocOwnershipTransfer-prototype"
    display_name = "GSuite Document External Ownership Transfer"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite", "Collection:Data from Information Repositories"]
    reports = {"MITRE ATT&CK": ["TA0009:T1213"]}
    default_severity = Severity.LOW
    default_description = "A GSuite document's ownership was transferred to an external party.\n"
    default_reference = (
        "https://support.google.com/drive/answer/2494892?hl=en&co=GENIE.Platform%3DDesktop&sjid=864417124752637253-EU"
    )
    default_runbook = "Verify that this document did not contain sensitive or private company information.\n"
    summary_attributes = ["actor:email"]

    def rule(self, event):
        if event.get("name") != "change_owner":
            return False
        if event.deep_get("parameters", "visibility") in (
            "shared_internally",
            "people_within_domain_with_link",
            "private",
        ):
            return False
        previous_owner = event.deep_get("parameters", "owner", default="<UNKNOWN USER>")
        new_owner = event.deep_get("parameters", "new_owner", default="<UNKNOWN USER>")
        previous_owner_domain = previous_owner.split("@")[1] if "@" in previous_owner else None
        new_owner_domain = new_owner.split("@")[1] if "@" in new_owner else None
        if previous_owner_domain is None or new_owner_domain is None:
            return False
        if previous_owner_domain != new_owner_domain:
            return True
        return False

    def title(self, event):
        actor = event.deep_get("actor", "email", default="<UNKNOWN USER>")
        previous_owner = event.deep_get("parameters", "owner", default="<UNKNOWN USER>")
        new_owner = event.deep_get("parameters", "new_owner", default="<UNKNOWN USER>")
        return f"User [{actor}] transferred document ownership from [{previous_owner}] to [{new_owner}]"

    tests = [
        RuleTest(
            name="Ownership Transferred Within Organization",
            expected_result=False,
            log={
                "actor": {"email": "alice@panther.com", "profileId": "1234567890"},
                "id": {
                    "applicationName": "drive",
                    "customerId": "C123abcde",
                    "time": "2025-08-12 18:41:56.232000000",
                    "uniqueQualifier": "1234567890",
                },
                "ipAddress": "1.2.3.4",
                "kind": "admin#reports#activity",
                "name": "change_owner",
                "parameters": {
                    "billable": True,
                    "doc_id": "1234567890",
                    "doc_title": "sensitive_document.xlsx",
                    "doc_type": "msexcel",
                    "new_owner": "bob@panther.com",
                    "owner": "alice@panther.com",
                    "primary_event": True,
                    "visibility": "shared_internally",
                },
                "type": "acl_change",
            },
        ),
        RuleTest(
            name="Document Transferred to External User",
            expected_result=True,
            log={
                "actor": {"email": "alice@panther.com", "profileId": "1234567890"},
                "id": {
                    "applicationName": "drive",
                    "customerId": "C123abcde",
                    "time": "2025-07-11 19:50:09.324000000",
                    "uniqueQualifier": "1234567890",
                },
                "kind": "admin#reports#activity",
                "name": "change_owner",
                "parameters": {
                    "billable": True,
                    "doc_id": "1234567890",
                    "doc_title": "sensitive_document.xlsx",
                    "doc_type": "msexcel",
                    "new_owner": "bob@example.com",
                    "owner": "alice@panther.com",
                    "primary_event": True,
                    "visibility": "unknown",
                },
                "type": "acl_change",
            },
        ),
        RuleTest(
            name="Document Transferred to Group within Organization",
            expected_result=False,
            log={
                "actor": {"email": "alice@panther.com", "profileId": "100606748236723241722"},
                "id": {
                    "applicationName": "drive",
                    "customerId": "C123abcde",
                    "time": "2025-07-07 23:50:22.743000000",
                    "uniqueQualifier": "1234567890",
                },
                "ipAddress": "1.2.3.4",
                "kind": "admin#reports#activity",
                "name": "change_owner",
                "parameters": {
                    "billable": True,
                    "doc_id": "1234567890",
                    "doc_title": "sensitive_document.xlsx",
                    "doc_type": "msexcel",
                    "new_owner": "Execs",
                    "new_owner_is_team_drive": True,
                    "new_owner_team_drive_id": "1234567890",
                    "originating_app_id": "1234567890",
                    "owner": "Engineering",
                    "owner_is_shared_drive": True,
                    "owner_is_team_drive": True,
                    "owner_team_drive_id": "1234567890",
                    "primary_event": True,
                    "shared_drive_id": "1234567890",
                    "team_drive_id": "1234567890",
                    "visibility": "shared_internally",
                },
                "type": "acl_change",
            },
        ),
    ]
