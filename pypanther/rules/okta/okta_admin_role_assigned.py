import re

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.okta import okta_alert_context


@panther_managed
class OktaAdminRoleAssigned(Rule):
    id = "Okta.AdminRoleAssigned-prototype"
    display_name = "Okta Admin Role Assigned"
    log_types = [LogType.OKTA_SYSTEM_LOG]
    tags = ["Identity & Access Management", "Okta", "Privilege Escalation:Valid Accounts"]
    reports = {"MITRE ATT&CK": ["TA0004:T1078"]}
    default_severity = Severity.INFO
    default_description = "A user has been granted administrative privileges in Okta"
    default_reference = "https://help.okta.com/en/prod/Content/Topics/Security/administrators-admin-comparison.htm"
    default_runbook = "Reach out to the user if needed to validate the activity"
    dedup_period_minutes = 15
    summary_attributes = ["eventType", "severity", "displayMessage", "p_any_ip_addresses"]
    ADMIN_PATTERN = re.compile("[aA]dministrator")

    def rule(self, event):
        return (
            event.get("eventType", None) == "user.account.privilege.grant"
            and event.deep_get("outcome", "result") == "SUCCESS"
            and bool(
                self.ADMIN_PATTERN.search(event.deep_get("debugContext", "debugData", "privilegeGranted", default="")),
            )
        )

    def dedup(self, event):
        return event.deep_get("debugContext", "debugData", "requestId", default="<UNKNOWN_REQUEST_ID>")

    def title(self, event):
        target = event.get("target", [{}])
        display_name = target[0].get("displayName", "MISSING DISPLAY NAME") if target else ""
        alternate_id = target[0].get("alternateId", "MISSING ALTERNATE ID") if target else ""
        privilege = event.deep_get("debugContext", "debugData", "privilegeGranted", default="<UNKNOWN_PRIVILEGE>")
        return f"{event.deep_get('actor', 'displayName')} <{event.deep_get('actor', 'alternateId')}> granted [{privilege}] privileges to {display_name} <{alternate_id}>"

    def alert_context(self, event):
        return okta_alert_context(event)

    def severity(self, event):
        if "Super administrator" in event.deep_get("debugContext", "debugData", "privilegeGranted", default=""):
            return "HIGH"
        return "INFO"

    tests = [
        RuleTest(
            name="Admin Access Assigned",
            expected_result=True,
            log={
                "uuid": "2a992f80-d1ad-4f62-900e-8c68bb72a21b",
                "published": "2020-11-25 21:27:03.496000000",
                "eventType": "user.account.privilege.grant",
                "version": "0",
                "severity": "INFO",
                "legacyEventType": "core.user.admin_privilege.granted",
                "displayMessage": "Grant user privilege",
                "actor": {
                    "id": "00uu1uuuuIlllaaaa356",
                    "type": "User",
                    "alternateId": "jack@acme.io",
                    "displayName": "Jack Naglieri",
                },
                "client": {
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Mac OS X",
                        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
                    },
                    "geographicalContext": {
                        "geolocation": {"lat": 37.7852, "lon": -122.3874},
                        "city": "San Francisco",
                        "state": "California",
                        "country": "United States",
                        "postalCode": "94105",
                    },
                    "zone": "null",
                    "ipAddress": "136.24.229.58",
                    "device": "Computer",
                },
                "request": {},
                "outcome": {"result": "SUCCESS"},
                "target": [
                    {
                        "id": "00u6eup97mAJZWYmP357",
                        "type": "User",
                        "alternateId": "alice@acme.io",
                        "displayName": "Alice Green",
                    },
                ],
                "transaction": {},
                "debugContext": {
                    "debugData": {
                        "privilegeGranted": "Organization administrator, Application administrator (all)",
                        "requestUri": "/api/internal/administrators/00u6eu8c68bb72a21b57",
                        "threatSuspected": "false",
                        "url": "/api/internal/administrators/00u6eu8c68bb72a21b57",
                        "requestId": "X777JJ9sssQQHHrrrQTyYQAABBE",
                    },
                },
                "authenticationContext": {},
                "securityContext": {},
            },
        ),
        RuleTest(
            name="Super Admin Access Assigned (High sev)",
            expected_result=True,
            log={
                "uuid": "2a992f80-d1ad-4f62-900e-8c68bb72a21b",
                "published": "2020-11-25 21:27:03.496000000",
                "eventType": "user.account.privilege.grant",
                "version": "0",
                "severity": "INFO",
                "legacyEventType": "core.user.admin_privilege.granted",
                "displayMessage": "Grant user privilege",
                "actor": {
                    "id": "00uu1uuuuIlllaaaa356",
                    "type": "User",
                    "alternateId": "jack@acme.io",
                    "displayName": "Jack Naglieri",
                },
                "client": {
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Mac OS X",
                        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
                    },
                    "geographicalContext": {
                        "geolocation": {"lat": 37.7852, "lon": -122.3874},
                        "city": "San Francisco",
                        "state": "California",
                        "country": "United States",
                        "postalCode": "94105",
                    },
                    "zone": "null",
                    "ipAddress": "136.24.229.58",
                    "device": "Computer",
                },
                "request": {},
                "outcome": {"result": "SUCCESS"},
                "target": [
                    {
                        "id": "00u6eup97mAJZWYmP357",
                        "type": "User",
                        "alternateId": "alice@acme.io",
                        "displayName": "Alice Green",
                    },
                ],
                "transaction": {},
                "debugContext": {
                    "debugData": {
                        "privilegeGranted": "Super administrator, Read only admin",
                        "requestUri": "/api/internal/administrators/00u6eu8c68bb72a21b57",
                        "threatSuspected": "false",
                        "url": "/api/internal/administrators/00u6eu8c68bb72a21b57",
                        "requestId": "X777JJ9sssQQHHrrrQTyYQAABBE",
                    },
                },
                "authenticationContext": {},
                "securityContext": {},
            },
        ),
    ]
