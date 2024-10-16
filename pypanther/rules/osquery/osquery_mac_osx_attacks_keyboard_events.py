from fnmatch import fnmatch

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class OsqueryMacOSXAttacksKeyboardEvents(Rule):
    id = "Osquery.Mac.OSXAttacksKeyboardEvents-prototype"
    display_name = "MacOS Keyboard Events"
    log_types = [LogType.OSQUERY_DIFFERENTIAL]
    tags = ["Osquery", "MacOS", "Malware", "Collection:Input Capture"]
    reports = {"MITRE ATT&CK": ["TA0009:T1056"]}
    default_severity = Severity.MEDIUM
    default_description = "A Key Logger has potentially been detected on a macOS system"
    default_runbook = "Verify the Application monitoring the keyboard taps"
    default_reference = "https://support.apple.com/en-us/HT204899"
    summary_attributes = ["name", "hostIdentifier", "action"]
    # sip protects against writing malware into the paths below.
    # additional apps can be added to this list based on your environments.
    #
    # more info: https://support.apple.com/en-us/HT204899
    APPROVED_PROCESS_PATHS = {"/System/*", "/usr/*", "/bin/*", "/sbin/*", "/var/*"}
    APPROVED_APPLICATION_NAMES = {"Adobe Photoshop CC 2019"}

    def rule(self, event):
        if "Keyboard_Event_Taps" not in event.get("name", ""):
            return False
        if event.get("action") != "added":
            return False
        process_path = event.deep_get("columns", "path", default="")
        if process_path == "":
            return False
        if event.deep_get("columns", "name") in self.APPROVED_APPLICATION_NAMES:
            return False
        # Alert if the process is running outside any of the approved paths
        # TODO: Convert this fnmatch pattern below to a helper
        return not any(fnmatch(process_path, p) for p in self.APPROVED_PROCESS_PATHS)

    def title(self, event):
        return f"Keylogger malware detected on [{event.get('hostIdentifier')}]"

    tests = [
        RuleTest(
            name="App running on Desktop that is watching keyboard events",
            expected_result=True,
            log={
                "name": "pack_osx-attacks_Keyboard_Event_Taps",
                "action": "added",
                "hostIdentifier": "test-host",
                "columns": {"path": "/Users/johnny/Desktop/Siri.app/Contents/MacOS/Siri", "pid": 100, "name": "Siri"},
            },
        ),
        RuleTest(
            name="App is running from approved path",
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
        RuleTest(
            name="Unrelated query does not alert",
            expected_result=False,
            log={
                "action": "added",
                "calendarTime": "2020-04-10 23:26:11.000000000",
                "columns": {
                    "blocks_size": "4096",
                    "inodes": "2448101320",
                    "path": "/",
                    "blocks": "61202533",
                    "blocks_available": "22755926",
                    "blocks_free": "58479522",
                    "device": "/dev/disk1s5",
                    "device_alias": "/dev/disk1s5",
                    "flags": "75550721",
                    "inodes_free": "2447613763",
                    "type": "apfs",
                },
                "counter": 28,
                "decorations": {"host_uuid": "0ec3540f-1dd9-4462-bd28-0f63b2611621", "hostname": "MacBook-Pro.local"},
                "epoch": 0,
                "hostIdentifier": "MacBook-Pro.local",
                "name": "pack/incident-response/mounts",
                "unixTime": 1586561171,
            },
        ),
    ]
