from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GSuiteWorkspaceTrustedDomainsAllowlist(Rule):
    id = "GSuite.Workspace.TrustedDomainsAllowlist-prototype"
    display_name = "GSuite Workspace Trusted Domain Allowlist Modified"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite"]
    default_severity = Severity.MEDIUM
    default_description = "A Workspace Admin Has Modified The Trusted Domains List\n"
    default_reference = "https://support.google.com/a/answer/6160020?hl=en&sjid=864417124752637253-EU"
    default_runbook = "Verify the intent of this modification. If intent cannot be verified, then an indicator search on the actor is advised.\n"
    summary_attributes = ["actor:email"]
    reports = {"MITRE ATT&CK": ["TA0003:T1098"]}

    def rule(self, event):
        return event.get("type") == "DOMAIN_SETTINGS" and event.get("name", "").endswith("_TRUSTED_DOMAINS")

    def title(self, event):
        return f"GSuite Workspace Trusted Domains Modified [{event.get('name', '<NO_EVENT_NAME>')}] with [{event.deep_get('parameters', 'DOMAIN_NAME', default='<NO_DOMAIN_NAME>')}] performed by [{event.deep_get('actor', 'email', default='<NO_ACTOR_FOUND>')}]"

    tests = [
        RuleTest(
            name="Workspace Admin Remove Trusted Domain",
            expected_result=True,
            log={
                "actor": {"callerType": "USER", "email": "user@example.io", "profileId": "110506209185950390992"},
                "id": {
                    "applicationName": "admin",
                    "customerId": "D12345",
                    "time": "2022-12-11 00:01:34.643000000",
                    "uniqueQualifier": "-2972206985263071668",
                },
                "kind": "admin#reports#activity",
                "name": "REMOVE_TRUSTED_DOMAINS",
                "p_source_label": "Staging",
                "parameters": {"DOMAIN_NAME": "evilexample.com"},
                "type": "DOMAIN_SETTINGS",
            },
        ),
        RuleTest(
            name="Workspace Admin Add Trusted Domain",
            expected_result=True,
            log={
                "actor": {"callerType": "USER", "email": "user@example.io", "profileId": "110506209185950390992"},
                "id": {
                    "applicationName": "admin",
                    "customerId": "D12345",
                    "time": "2022-12-10 23:59:24.470000000",
                    "uniqueQualifier": "-334478670839567761",
                },
                "kind": "admin#reports#activity",
                "name": "ADD_TRUSTED_DOMAINS",
                "parameters": {"DOMAIN_NAME": "evilexample.com"},
                "type": "DOMAIN_SETTINGS",
            },
        ),
        RuleTest(
            name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to MANAGE_ACCESS",
            expected_result=False,
            log={
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
                    "NEW_VALUE": "MANAGE_ACCESS",
                    "OLD_VALUE": "READ_WRITE_ACCESS",
                    "ORG_UNIT_NAME": "Example IO",
                    "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN",
                },
                "type": "CALENDAR_SETTINGS",
            },
        ),
        RuleTest(
            name="ListObject Type",
            expected_result=False,
            log={
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
