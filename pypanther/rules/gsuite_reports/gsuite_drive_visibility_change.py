import json
from unittest.mock import MagicMock

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.gsuite import gsuite_parameter_lookup as param_lookup


@panther_managed
class GSuiteDriveVisibilityChanged(Rule):
    id = "GSuite.DriveVisibilityChanged-prototype"
    display_name = "GSuite External Drive Document"
    enabled = False
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite", "Collection:Data from Information Repositories", "Configuration Required"]
    reports = {"MITRE ATT&CK": ["TA0009:T1213"]}
    default_severity = Severity.LOW
    default_description = "A Google drive resource became externally accessible.\n"
    default_reference = "https://support.google.com/a/users/answer/12380484?hl=en&sjid=864417124752637253-EU"
    default_runbook = "Investigate whether the drive document is appropriate to be publicly accessible.\n"
    summary_attributes = ["actor:email"]
    dedup_period_minutes = 360
    # Add any domain name(s) that you expect to share documents with in the ALLOWED_DOMAINS set
    ALLOWED_DOMAINS = set()
    PUBLIC_PROVIDERS = {
        "gmail.com",
        "yahoo.com",
        "outlook.com",
        "aol.com",
        "yandex.com",
        "protonmail.com",
        "pm.me",
        "icloud.com",
        "tutamail.com",
        "tuta.io",
        "keemail.me",
        "mail.com",
        "zohomail.com",
        "hotmail.com",
        "msn.com",
    }
    VISIBILITY = {
        "people_with_link",
        "people_within_domain_with_link",
        "public_on_the_web",
        "shared_externally",
        "unknown",
    }
    ALERT_DETAILS = {}
    # Events where documents have changed perms due to parent folder change
    INHERITANCE_EVENTS = {
        "change_user_access_hierarchy_reconciled",
        "change_document_access_scope_hierarchy_reconciled",
    }

    def init_alert_details(self, log):
        self.ALERT_DETAILS[log] = {
            "ACCESS_SCOPE": "<UNKNOWN_ACCESS_SCOPE>",
            "DOC_TITLE": "<UNKNOWN_TITLE>",
            "NEW_VISIBILITY": "<UNKNOWN_VISIBILITY>",
            "TARGET_USER_EMAILS": ["<UNKNOWN_USER>"],
            "TARGET_DOMAIN": "<UNKNOWN_DOMAIN>",
        }

    def user_is_external(self, target_user):
        # We need to type-cast ALLOWED_DOMAINS for unit testing mocks
        if isinstance(self.ALLOWED_DOMAINS, MagicMock):
            self.ALLOWED_DOMAINS = set(json.loads(self.ALLOWED_DOMAINS()))  # pylint: disable=not-callable
        for domain in self.ALLOWED_DOMAINS:
            if domain in target_user:
                return False
        return True

    def rule(self, event):
        # pylint: disable=too-complex
        if event.deep_get("id", "applicationName") != "drive":
            return False
        # Events that have the types in INHERITANCE_EVENTS are
        # changes to documents and folders that occur due to
        # a change in the parent folder's permission. We ignore
        # these events to prevent every folder change from
        # generating multiple alerts.
        if event.get("name") in self.INHERITANCE_EVENTS:
            return False
        log = event.get("p_row_id")
        self.init_alert_details(log)
        # We need to type-cast ALLOWED_DOMAINS for unit testing mocks
        if isinstance(self.ALLOWED_DOMAINS, MagicMock):
            self.ALLOWED_DOMAINS = set(json.loads(self.ALLOWED_DOMAINS()))  # pylint: disable=not-callable
        # For GSuite.ActivityEvent, each log is a single event.
        # Check if this event is a visibility change for a domain
        if (
            event.get("type") == "acl_change"
            and event.get("name") == "change_document_visibility"
            and (param_lookup(event.get("parameters", {}), "new_value") != ["private"])
            and (param_lookup(event.get("parameters", {}), "target_domain") not in self.ALLOWED_DOMAINS)
            and (param_lookup(event.get("parameters", {}), "visibility") in self.VISIBILITY)
        ):
            self.ALERT_DETAILS[log]["TARGET_DOMAIN"] = param_lookup(event.get("parameters", {}), "target_domain")
            self.ALERT_DETAILS[log]["NEW_VISIBILITY"] = param_lookup(event.get("parameters", {}), "visibility")
            self.ALERT_DETAILS[log]["DOC_TITLE"] = param_lookup(event.get("parameters", {}), "doc_title")
            if param_lookup(event.get("parameters", {}), "new_value") != ["none"]:
                self.ALERT_DETAILS[log]["ACCESS_SCOPE"] = param_lookup(event.get("parameters", {}), "new_value")
            return True
        # For visibility changes that apply to a user
        if (
            event.get("type") == "acl_change"
            and event.get("name") == "change_user_access"
            and (param_lookup(event.get("parameters", {}), "new_value") != ["none"])
            and self.user_is_external(param_lookup(event.get("parameters", {}), "target_user"))
        ):
            if self.ALERT_DETAILS[log]["TARGET_USER_EMAILS"] != ["<UNKNOWN_USER>"]:
                self.ALERT_DETAILS[log]["TARGET_USER_EMAILS"].append(
                    param_lookup(event.get("parameters", {}), "target_user"),
                )
            else:
                self.ALERT_DETAILS[log]["TARGET_USER_EMAILS"] = [
                    param_lookup(event.get("parameters", {}), "target_user"),
                ]
                self.ALERT_DETAILS[log]["DOC_TITLE"] = param_lookup(event.get("parameters", {}), "doc_title")
                self.ALERT_DETAILS[log]["ACCESS_SCOPE"] = param_lookup(event.get("parameters", {}), "new_value")
            return True
        return False

    def alert_context(self, event):
        log = event.get("p_row_id")
        if self.ALERT_DETAILS[log]["TARGET_USER_EMAILS"] != ["<UNKNOWN_USER>"]:
            return {"target users": self.ALERT_DETAILS[log]["TARGET_USER_EMAILS"]}
        return {}

    def dedup(self, event):
        return event.deep_get("actor", "email", default="<UNKNOWN_USER>")

    def title(self, event):
        log = event.get("p_row_id")
        if self.ALERT_DETAILS[log]["TARGET_USER_EMAILS"] != ["<UNKNOWN_USER>"]:
            if len(self.ALERT_DETAILS[log]["TARGET_USER_EMAILS"]) == 1:
                sharing_scope = self.ALERT_DETAILS[log]["TARGET_USER_EMAILS"][0]
            else:
                sharing_scope = "multiple users"
            if self.ALERT_DETAILS[log]["NEW_VISIBILITY"] == "shared_externally":
                sharing_scope += " (outside the document's current domain)"
        elif self.ALERT_DETAILS[log]["TARGET_DOMAIN"] == "all":
            sharing_scope = "the entire internet"
            if self.ALERT_DETAILS[log]["NEW_VISIBILITY"] == "people_with_link":
                sharing_scope += " (anyone with the link)"
            elif self.ALERT_DETAILS[log]["NEW_VISIBILITY"] == "public_on_the_web":
                sharing_scope += " (link not required)"
        else:
            sharing_scope = f"the {self.ALERT_DETAILS[log]['TARGET_DOMAIN']} domain"
            if self.ALERT_DETAILS[log]["NEW_VISIBILITY"] == "people_within_domain_with_link":
                sharing_scope += f" (anyone in {self.ALERT_DETAILS[log]['TARGET_DOMAIN']} with the link)"
            elif self.ALERT_DETAILS[log]["NEW_VISIBILITY"] == "public_in_the_domain":
                sharing_scope += f" (anyone in {self.ALERT_DETAILS[log]['TARGET_DOMAIN']})"
        # alert_access_scope = ALERT_DETAILS[log]["ACCESS_SCOPE"][0].replace("can_", "")
        return f"User [{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}] made documents externally visible"

    def severity(self, event):
        log = event.get("p_row_id")
        if self.ALERT_DETAILS[log]["TARGET_USER_EMAILS"] != ["<UNKNOWN_USER>"]:
            for address in self.ALERT_DETAILS[log]["TARGET_USER_EMAILS"]:
                domain = address.split("@")[1]
                if domain in self.PUBLIC_PROVIDERS:
                    return "LOW"
        return "INFO"

    tests = [
        RuleTest(
            name="Access Event",
            expected_result=False,
            log={
                "p_log_type": "GSuite.ActivityEvent",
                "p_row_id": "111222",
                "actor": {"email": "bobert@example.com"},
                "id": {"applicationName": "drive"},
                "type": "access",
                "name": "upload",
            },
        ),
        RuleTest(
            name="ACL Change without Visibility Change",
            expected_result=False,
            log={
                "p_log_type": "GSuite.ActivityEvent",
                "p_row_id": "111222",
                "actor": {"email": "bobert@example.com"},
                "id": {"applicationName": "drive"},
                "type": "acl_change",
                "name": "shared_drive_settings_change",
            },
        ),
        RuleTest(
            name="Doc Became Public - Link (Unrestricted)",
            expected_result=True,
            log={
                "p_log_type": "GSuite.ActivityEvent",
                "p_row_id": "111222",
                "actor": {"email": "bobert@gmail.com"},
                "id": {"applicationName": "drive"},
                "type": "acl_change",
                "name": "change_document_visibility",
                "parameters": {
                    "visibility_change": "external",
                    "doc_title": "my shared document",
                    "target_domain": "all",
                    "visibility": "people_with_link",
                    "new_value": ["people_with_link"],
                },
            },
        ),
        RuleTest(
            name="Doc Became Public - Link (Allowlisted Domain Not Configured)",
            expected_result=True,
            log={
                "p_log_type": "GSuite.ActivityEvent",
                "p_row_id": "111222",
                "actor": {"email": "bobert@example.com"},
                "id": {"applicationName": "drive"},
                "type": "acl_change",
                "name": "change_document_visibility",
                "parameters": {
                    "visibility_change": "external",
                    "doc_title": "my shared document",
                    "target_domain": "example.com",
                    "visibility": "people_within_domain_with_link",
                    "new_value": ["people_with_link"],
                },
            },
        ),
        RuleTest(
            name="Doc Became Public - Link (Allowlisted Domain Is Configured)",
            expected_result=False,
            mocks=[RuleMock(object_name="ALLOWED_DOMAINS", return_value='[\n  "example.com"\n]')],
            log={
                "p_log_type": "GSuite.ActivityEvent",
                "p_row_id": "111222",
                "actor": {"email": "bobert@example.com"},
                "id": {"applicationName": "drive"},
                "type": "acl_change",
                "name": "change_document_visibility",
                "parameters": {
                    "visibility_change": "external",
                    "doc_title": "my shared document",
                    "target_domain": "example.com",
                    "visibility": "people_within_domain_with_link",
                    "new_value": ["people_with_link"],
                },
            },
        ),
        RuleTest(
            name="Doc Became Private - Link",
            expected_result=False,
            log={
                "p_log_type": "GSuite.ActivityEvent",
                "p_row_id": "111222",
                "actor": {"email": "bobert@example.com"},
                "id": {"applicationName": "drive"},
                "type": "acl_change",
                "name": "change_document_visibility",
                "parameters": {
                    "visibility_change": "external",
                    "doc_title": "my shared document",
                    "target_domain": "all",
                    "visibility": "people_with_link",
                    "new_value": ["private"],
                },
            },
        ),
        RuleTest(
            name="Doc Became Public - User",
            expected_result=True,
            log={
                "p_log_type": "GSuite.ActivityEvent",
                "actor": {"email": "bobert@example.com"},
                "id": {"applicationName": "drive"},
                "kind": "admin#reports#activity",
                "ipAddress": "1.1.1.1",
                "type": "acl_change",
                "name": "change_user_access",
                "parameters": {
                    "primary_event": True,
                    "visibility_change": "external",
                    "target_user": "someone@random.com",
                    "old_value": ["none"],
                    "new_value": ["can_view"],
                    "old_visibility": "people_within_domain_with_link",
                    "doc_title": "Hosted Accounts",
                    "visibility": "shared_externally",
                },
            },
        ),
        RuleTest(
            name="Doc Became Public - User (Multiple)",
            expected_result=True,
            log={
                "p_log_type": "GSuite.ActivityEvent",
                "actor": {"email": "bobert@example.com"},
                "id": {"applicationName": "drive"},
                "kind": "admin#reports#activity",
                "ipAddress": "1.1.1.1",
                "type": "acl_change",
                "name": "change_user_access",
                "parameters": {
                    "primary_event": True,
                    "visibility_change": "external",
                    "target_user": "someone@random.com",
                    "old_value": ["none"],
                    "new_value": ["can_view"],
                    "old_visibility": "people_within_domain_with_link",
                    "doc_title": "Hosted Accounts",
                    "visibility": "shared_externally",
                },
            },
        ),
        RuleTest(
            name="Doc Inherits Folder Permissions",
            expected_result=False,
            log={
                "p_log_type": "GSuite.ActivityEvent",
                "p_row_id": "111222",
                "actor": {"email": "bobert@example.com"},
                "id": {"applicationName": "drive"},
                "type": "acl_change",
                "name": "change_user_access_hierarchy_reconciled",
                "parameters": {"visibility_change": "internal"},
            },
        ),
        RuleTest(
            name="Doc Inherits Folder Permissions - Sharing Link",
            expected_result=False,
            log={
                "p_log_type": "GSuite.ActivityEvent",
                "p_row_id": "111222",
                "actor": {"email": "bobert@example.com"},
                "id": {"applicationName": "drive"},
                "type": "acl_change",
                "name": "change_document_access_scope_hierarchy_reconciled",
                "parameters": {"visibility_change": "internal"},
            },
        ),
        RuleTest(
            name="Doc Became Public - Public email provider",
            expected_result=True,
            log={
                "p_log_type": "GSuite.ActivityEvent",
                "actor": {"email": "bobert@example.com"},
                "id": {"applicationName": "drive"},
                "kind": "admin#reports#activity",
                "ipAddress": "1.1.1.1",
                "type": "acl_change",
                "name": "change_user_access",
                "parameters": {
                    "primary_event": True,
                    "visibility_change": "external",
                    "target_user": "someone@yandex.com",
                    "old_value": ["none"],
                    "new_value": ["can_view"],
                    "old_visibility": "people_within_domain_with_link",
                    "doc_title": "Hosted Accounts",
                    "visibility": "shared_externally",
                },
            },
        ),
        RuleTest(
            name="Doc Shared With Multiple Users All From ALLOWED_DOMAINS",
            expected_result=False,
            mocks=[RuleMock(object_name="ALLOWED_DOMAINS", return_value='[\n  "example.com", "notexample.com"\n]')],
            log={
                "p_log_type": "GSuite.ActivityEvent",
                "actor": {"email": "bobert@example.com"},
                "id": {"applicationName": "drive"},
                "kind": "admin#reports#activity",
                "ipAddress": "1.1.1.1",
                "type": "acl_change",
                "name": "change_user_access",
                "parameters": {
                    "primary_event": True,
                    "visibility_change": "external",
                    "target_user": "someone@notexample.com",
                    "old_value": ["none"],
                    "new_value": ["can_view"],
                    "old_visibility": "people_within_domain_with_link",
                    "doc_title": "Hosted Accounts",
                    "visibility": "shared_externally",
                },
            },
        ),
    ]
