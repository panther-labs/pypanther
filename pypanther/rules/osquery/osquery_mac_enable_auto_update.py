from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class OsqueryMacAutoUpdateEnabled(Rule):
    id = "Osquery.Mac.AutoUpdateEnabled-prototype"
    display_name = "OSQuery Reports Application Firewall Disabled"
    log_types = [LogType.OSQUERY_DIFFERENTIAL]
    tags = ["Osquery", "MacOS", "Security Control", "Defense Evasion:Impair Defenses"]
    reports = {"CIS": ["1.2"], "MITRE ATT&CK": ["TA0005:T1562"]}
    default_severity = Severity.MEDIUM
    dedup_period_minutes = 1440
    default_description = "Verifies that MacOS has automatic software updates enabled.\n"
    default_runbook = "Enable the auto updates on the host.\n"
    default_reference = "https://support.apple.com/en-gb/guide/mac-help/mchlpx1065/mac"
    summary_attributes = ["name", "action", "p_any_ip_addresses", "p_any_domain_names"]

    def rule(self, event):
        # Send an alert if not set to "true"
        return (
            "SoftwareUpdate" in event.get("name", [])
            and event.get("action") == "added"
            and (event.deep_get("columns", "domain") == "com.apple.SoftwareUpdate")
            and (event.deep_get("columns", "key") == "AutomaticCheckEnabled")
            and (event.deep_get("columns", "value") == "false")
        )

    tests = [
        RuleTest(
            name="Auto Updates Disabled",
            expected_result=True,
            log={
                "columns": {"domain": "com.apple.SoftwareUpdate", "key": "AutomaticCheckEnabled", "value": "false"},
                "action": "added",
                "name": "pack/mac-cis/SoftwareUpdate",
            },
        ),
        RuleTest(
            name="Auto Updates Enabled",
            expected_result=False,
            log={
                "columns": {"domain": "com.apple.SoftwareUpdate", "key": "AutomaticCheckEnabled", "value": "true"},
                "action": "added",
                "name": "pack/mac-cis/SoftwareUpdate",
            },
        ),
        RuleTest(
            name="Wrong Key",
            expected_result=False,
            log={
                "columns": {"domain": "com.apple.SoftwareUpdate", "key": "LastFullSuccessfulDate", "value": "false"},
                "action": "added",
                "name": "pack/mac-cis/SoftwareUpdate",
            },
        ),
    ]
