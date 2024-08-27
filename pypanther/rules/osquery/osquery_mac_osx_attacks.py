from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

osquery_mac_osx_attacks_tests: list[RuleTest] = [
    RuleTest(
        name="Valid malware discovered",
        expected_result=True,
        log={
            "name": "pack_osx-attacks_Leverage-A_1",
            "action": "added",
            "hostIdentifier": "test-host",
            "columns": {"path": "/Users/johnny/Desktop/Siri.app/Contents/MacOS/Siri", "pid": 100, "name": "Siri"},
        },
    ),
    RuleTest(
        name="Keyboard event taps query is ignored",
        expected_result=False,
        log={
            "name": "pack_osx-attacks_Keyboard_Event_Taps",
            "action": "added",
            "hostIdentifier": "test-host",
            "columns": {
                "path": "/System/Library/CoreServices/Siri.app/Contents/MacOS/Siri",
                "pid": 100,
                "name": "Siri",
            },
        },
    ),
]


@panther_managed
class OsqueryMacOSXAttacks(Rule):
    id = "Osquery.Mac.OSXAttacks-prototype"
    display_name = "macOS Malware Detected with osquery"
    log_types = [LogType.OSQUERY_DIFFERENTIAL]
    tags = ["Osquery", "MacOS", "Malware", "Resource Development:Develop Capabilities"]
    reports = {"MITRE ATT&CK": ["TA0042:T1588"]}
    default_severity = Severity.MEDIUM
    default_description = "Malware has potentially been detected on a macOS system"
    default_runbook = "Check the executable against VirusTotal"
    default_reference = "https://github.com/osquery/osquery/blob/master/packs/osx-attacks.conf"
    summary_attributes = ["name", "hostIdentifier", "action"]
    tests = osquery_mac_osx_attacks_tests

    def rule(self, event):
        if "osx-attacks" not in event.get("name", ""):
            return False
        # There is another rule specifically for this query
        if "Keyboard_Event_Taps" in event.get("name", ""):
            return False
        if event.get("action") != "added":
            return False
        return True

    def title(self, event):
        return f"MacOS malware detected on [{event.get('hostIdentifier')}]"
