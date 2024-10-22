import datetime

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.base import pattern_match, pattern_match_list


@panther_managed
class GSuiteDriveExternalFileShare(Rule):
    id = "GSuite.Drive.ExternalFileShare-prototype"
    display_name = "External GSuite File Share"
    enabled = False
    log_types = [LogType.GSUITE_REPORTS]
    tags = ["GSuite", "Security Control", "Configuration Required", "Collection:Data from Information Repositories"]
    reports = {"MITRE ATT&CK": ["TA0009:T1213"]}
    default_severity = Severity.HIGH
    default_description = "An employee shared a sensitive file externally with another organization"
    default_runbook = "Contact the employee who made the share and make sure they redact the access. If the share was legitimate, add to the EXCEPTION_PATTERNS in the detection.\n"
    default_reference = (
        "https://support.google.com/docs/answer/2494822?hl=en&co=GENIE.Platform%3DiOS&sjid=864417124752637253-EU"
    )
    COMPANY_DOMAIN = "your-company-name.com"
    # The glob pattern for the document title (lowercased)
    # allow any title "all"
    # Allow any user
    # "all"
    # Allow any user in a specific domain
    # "*@acme.com"
    # Allow any user
    # "all"
    # Allow any user in a specific domain
    # "*@acme.com"
    # The time limit for how long the file share stays valid
    # The time limit for how long the file share stays valid
    EXCEPTION_PATTERNS = {
        "1 document title p*": {
            "allowed_to_send": {"alice@acme.com", "samuel@acme.com", "nathan@acme.com", "barry@acme.com"},
            "allowed_to_receive": {"alice@abc.com", "samuel@abc.com", "nathan@abc.com", "barry@abc.com"},
            "allowed_until": datetime.datetime(year=2030, month=6, day=2),
        },
        "2 document title p*": {
            "allowed_to_send": {"alice@abc.com"},
            "allowed_to_receive": {"*@acme.com"},
            "allowed_until": datetime.datetime(year=2030, month=6, day=2),
        },
    }

    def _check_acl_change_event(self, actor_email, acl_change_event):
        parameters = {p.get("name", ""): p.get("value") or p.get("multiValue") for p in acl_change_event["parameters"]}
        doc_title = parameters.get("doc_title", "TITLE_UNKNOWN")
        old_visibility = parameters.get("old_visibility", "OLD_VISIBILITY_UNKNOWN")
        new_visibility = parameters.get("visibility", "NEW_VISIBILITY_UNKNOWN")
        target_user = parameters.get("target_user") or parameters.get("target_domain") or "USER_UNKNOWN"
        current_time = datetime.datetime.now()
        if (
            new_visibility == "shared_externally"
            and old_visibility == "private"
            and (not target_user.endswith(f"@{self.COMPANY_DOMAIN}"))
        ):
            # This is a dangerous share, check exceptions:
            for pattern, details in self.EXCEPTION_PATTERNS.items():
                proper_title = pattern_match(doc_title.lower(), pattern) or pattern == "all"
                proper_sender = pattern_match_list(actor_email, details.get("allowed_to_send")) or details.get(
                    "allowed_to_send",
                ) == {"all"}
                proper_receiver = pattern_match_list(target_user, details.get("allowed_to_receive")) or details.get(
                    "allowed_to_receive",
                ) == {"all"}
                if proper_title and proper_sender and proper_receiver and (current_time < details.get("allowed_until")):
                    return False
            # No exceptions match.
            # Return the event summary (which is True) to alert & use in title.
            return {"actor": actor_email, "doc_title": doc_title, "target_user": target_user}
        return False

    def rule(self, event):
        application_name = event.deep_get("id", "applicationName")
        events = event.get("events")
        actor_email = event.deep_get("actor", "email", default="EMAIL_UNKNOWN")
        if application_name == "drive" and events and ("acl_change" in set(e["type"] for e in events)):
            # If any of the events in this record are a dangerous file share, alert:
            return any(self._check_acl_change_event(actor_email, acl_change_event) for acl_change_event in events)
        return False

    def title(self, event):
        events = event.get("events", [])
        actor_email = event.deep_get("actor", "email", default="EMAIL_UNKNOWN")
        matching_events = [
            self._check_acl_change_event(actor_email, acl_change_event)
            for acl_change_event in events
            if self._check_acl_change_event(actor_email, acl_change_event)
        ]
        if matching_events:
            len_events = len(matching_events)
            first_event = matching_events[0]
            actor = first_event.get("actor", "ACTOR_UNKNOWN")
            doc_title = first_event.get("doc_title", "DOC_TITLE_UNKNOWN")
            target_user = first_event.get("target_user", "USER_UNKNOWN")
            if len(matching_events) > 1:
                return (
                    f"Multiple dangerous shares ({len_events}) by [{actor}], including "
                    + f'"{doc_title}" to {target_user}'
                )
            return f'Dangerous file share by [{actor}]: "{doc_title}" to {target_user}'
        return "No matching events, but DangerousShares still fired"

    tests = [
        RuleTest(
            name="Dangerous Share of Known Document with a Missing User",
            expected_result=True,
            log={
                "kind": "admin#reports#activity",
                "id": {
                    "time": "2020-09-07T15:50:49.617Z",
                    "uniqueQualifier": "1111111111111111111",
                    "applicationName": "drive",
                    "customerId": "C010qxghg",
                },
                "actor": {"email": "example@acme.com", "profileId": "1111111111111111111"},
                "events": [
                    {
                        "type": "acl_change",
                        "name": "change_user_access",
                        "parameters": [
                            {"name": "primary_event", "boolValue": True},
                            {"name": "visibility_change", "value": "external"},
                            {"name": "target_user", "value": "outside@acme.com"},
                            {"name": "old_visibility", "value": "private"},
                            {"name": "doc_id", "value": "1111111111111111111"},
                            {"name": "doc_type", "value": "document"},
                            {"name": "doc_title", "value": "1 Document Title Primary"},
                            {"name": "visibility", "value": "shared_externally"},
                            {"name": "originating_app_id", "value": "1111111111111111111"},
                            {"name": "owner_is_shared_drive", "boolValue": False},
                            {"name": "owner_is_team_drive", "boolValue": False},
                            {"name": "old_value", "multiValue": ["none"]},
                            {"name": "new_value", "multiValue": ["can_edit"]},
                        ],
                    },
                ],
            },
        ),
        RuleTest(
            name="Dangerous Share of Unknown Document",
            expected_result=True,
            log={
                "kind": "admin#reports#activity",
                "id": {
                    "time": "2020-09-07T15:50:49.617Z",
                    "uniqueQualifier": "1111111111111111111",
                    "applicationName": "drive",
                    "customerId": "C010qxghg",
                },
                "actor": {"email": "example@acme.com", "profileId": "1111111111111111111"},
                "events": [
                    {
                        "type": "acl_change",
                        "name": "change_user_access",
                        "parameters": [
                            {"name": "primary_event", "boolValue": True},
                            {"name": "visibility_change", "value": "external"},
                            {"name": "target_domain", "value": "external.com"},
                            {"name": "old_visibility", "value": "private"},
                            {"name": "doc_id", "value": "1111111111111111111"},
                            {"name": "doc_type", "value": "document"},
                            {"name": "doc_title", "value": "Untitled document"},
                            {"name": "visibility", "value": "shared_externally"},
                            {"name": "originating_app_id", "value": "1111111111111111111"},
                            {"name": "owner_is_shared_drive", "boolValue": False},
                            {"name": "owner_is_team_drive", "boolValue": False},
                            {"name": "old_value", "multiValue": ["none"]},
                            {"name": "new_value", "multiValue": ["can_edit"]},
                        ],
                    },
                ],
            },
        ),
        RuleTest(
            name="Share Allowed by Exception",
            expected_result=False,
            log={
                "kind": "admin#reports#activity",
                "id": {
                    "time": "2020-07-07T15:50:49.617Z",
                    "uniqueQualifier": "1111111111111111111",
                    "applicationName": "drive",
                    "customerId": "C010qxghg",
                },
                "actor": {"email": "alice@acme.com", "profileId": "1111111111111111111"},
                "events": [
                    {
                        "type": "acl_change",
                        "name": "change_user_access",
                        "parameters": [
                            {"name": "primary_event", "boolValue": True},
                            {"name": "billable", "boolValue": True},
                            {"name": "visibility_change", "value": "external"},
                            {"name": "target_user", "value": "samuel@abc.com"},
                            {"name": "old_visibility", "value": "private"},
                            {"name": "doc_id", "value": "1111111111111111111"},
                            {"name": "doc_type", "value": "document"},
                            {"name": "doc_title", "value": "1 Document Title Pattern"},
                            {"name": "visibility", "value": "shared_externally"},
                            {"name": "originating_app_id", "value": "1111111111111111111"},
                            {"name": "owner_is_shared_drive", "boolValue": False},
                            {"name": "owner_is_team_drive", "boolValue": False},
                            {"name": "old_value", "multiValue": ["none"]},
                            {"name": "new_value", "multiValue": ["people_within_domain_with_link"]},
                        ],
                    },
                ],
            },
        ),
        RuleTest(
            name="Share Allowed by Exception - 2",
            expected_result=False,
            log={
                "kind": "admin#reports#activity",
                "id": {
                    "time": "2020-07-07T15:50:49.617Z",
                    "uniqueQualifier": "1111111111111111111",
                    "applicationName": "drive",
                    "customerId": "C010qxghg",
                },
                "actor": {"email": "alice@abc.com", "profileId": "1111111111111111111"},
                "events": [
                    {
                        "type": "acl_change",
                        "name": "change_user_access",
                        "parameters": [
                            {"name": "primary_event", "boolValue": True},
                            {"name": "billable", "boolValue": True},
                            {"name": "visibility_change", "value": "external"},
                            {"name": "target_user", "value": "samuel@acme.com"},
                            {"name": "old_visibility", "value": "private"},
                            {"name": "doc_id", "value": "1111111111111111111"},
                            {"name": "doc_type", "value": "document"},
                            {"name": "doc_title", "value": "2 Document Title Pattern"},
                            {"name": "visibility", "value": "shared_externally"},
                            {"name": "originating_app_id", "value": "1111111111111111111"},
                            {"name": "owner_is_shared_drive", "boolValue": False},
                            {"name": "owner_is_team_drive", "boolValue": False},
                            {"name": "old_value", "multiValue": ["none"]},
                            {"name": "new_value", "multiValue": ["people_within_domain_with_link"]},
                        ],
                    },
                ],
            },
        ),
    ]
