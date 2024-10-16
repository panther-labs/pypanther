from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GSuiteWorkspaceGmailPredeliveryScanningDisabled(Rule):
    id = "GSuite.Workspace.GmailPredeliveryScanningDisabled-prototype"
    display_name = "GSuite Workspace Gmail Pre-Delivery Message Scanning Disabled"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite"]
    reports = {"MITRE ATT&CK": ["TA0001:T1566"]}
    default_severity = Severity.MEDIUM
    default_description = "A Workspace Admin Has Disabled Pre-Delivery Scanning For Gmail.\n"
    default_reference = "https://support.google.com/a/answer/7380368"
    default_runbook = "Pre-delivery scanning is a feature in Gmail that subjects suspicious emails to additional automated scrutiny by Google.\nIf this change was not intentional, inspect the other actions taken by this actor.\n"
    summary_attributes = ["actor:email"]

    def rule(self, event):
        # the shape of the items in parameters can change a bit ( like NEW_VALUE can be an array )
        #  when the applicationName is something other than admin
        if event.deep_get("id", "applicationName", default="").lower() != "admin":
            return False
        if all(
            [
                event.get("name", "") == "CHANGE_APPLICATION_SETTING",
                event.deep_get("parameters", "APPLICATION_NAME", default="").lower() == "gmail",
                event.deep_get("parameters", "NEW_VALUE", default="").lower() == "true",
                event.deep_get("parameters", "SETTING_NAME", default="")
                == "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email",
            ],
        ):
            return True
        return False

    def title(self, event):
        return f"GSuite Gmail Enhanced Pre-Delivery Scanning was disabled for [{event.deep_get('parameters', 'ORG_UNIT_NAME', default='<NO_ORG_UNIT_NAME>')}] by [{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}]"

    tests = [
        RuleTest(
            name="Workspace Admin Disables Enhanced Pre-Delivery Scanning",
            expected_result=True,
            log={
                "actor": {"callerType": "USER", "email": "example@example.io", "profileId": "12345"},
                "id": {
                    "applicationName": "admin",
                    "customerId": "D12345",
                    "time": "2022-12-11 03:42:54.859000000",
                    "uniqueQualifier": "-12345",
                },
                "ipAddress": "12.12.12.12",
                "kind": "admin#reports#activity",
                "name": "CHANGE_APPLICATION_SETTING",
                "parameters": {
                    "APPLICATION_EDITION": "business_plus_2021",
                    "APPLICATION_NAME": "Gmail",
                    "NEW_VALUE": "true",
                    "ORG_UNIT_NAME": "Example IO",
                    "SETTING_NAME": "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email",
                },
                "type": "APPLICATION_SETTINGS",
            },
        ),
        RuleTest(
            name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_ONLY_ACCESS",
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
                    "NEW_VALUE": "READ_ONLY_ACCESS",
                    "OLD_VALUE": "DEFAULT",
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
