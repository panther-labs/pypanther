from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import crowdstrike_detection_alert_context, get_crowdstrike_field

crowdstrike_detectionpassthrough_tests: list[RuleTest] = [
    RuleTest(
        name="Low Severity Finding",
        expected_result=True,
        log={
            "cid": "11111111111111111111111111111111",
            "Technique": "PUP",
            "ProcessId": 377077835340488700,
            "AgentIdString": "00000000000000000000000000000000",
            "DetectName": "NGAV",
            "ComputerName": "macbook",
            "ProcessStartTime": "2021-09-18 20:38:51Z",
            "GrandparentCommandLine": "/sbin/launchd",
            "MACAddress": "aa-00-00-00-00-00",
            "CommandLine": "/Applications/app.app/Contents/MacOS/pup app",
            "Objective": "Falcon Detection Method",
            "Nonce": 1,
            "SHA256String": "3333333333333333333333333333333333333333333333333333333333333333",
            "ExternalApiType": "Event_DetectionSummaryEvent",
            "PatternDispositionValue": 2176,
            "DetectId": "ldt:00000000000000000000000000000000:222222222222222222",
            "Severity": 2,
            "PatternDispositionDescription": "Prevention/Quarantine, process was blocked from execution and quarantine was attempted.",
            "SeverityName": "Low",
            "MD5String": "33333333333333333333333333333333",
            "EventUUID": "33333333333333333333333333333333",
            "UserName": "bobert",
            "FilePath": "/Applications/app.app/Contents/MacOS/",
            "timestamp": "2021-09-18 20:38:52Z",
            "ParentCommandLine": "/usr/libexec/runningboardd",
            "DetectDescription": "This file is classified as Adware/PUP based on its SHA256 hash.",
            "LocalIP": "192.168.1.1",
            "ProcessEndTime": "1970-01-01 00:00:00Z",
            "SHA1String": "0000000000000000000000000000000000000000",
            "OriginSourceIpAddress": "",
            "GrandparentImageFileName": "/sbin/launchd",
            "MachineDomain": "",
            "ParentImageFileName": "/usr/libexec/runningboardd",
            "FalconHostLink": "https://falcon.us-2.crowdstrike.com/activity/detections/detail/00000000000000000000000000000000/222222222222222222?",
            "UTCTimestamp": "2021-09-18 20:38:52Z",
            "FileName": "pup app",
            "ParentProcessId": 376330001421757630,
            "EventType": "Event_ExternalApiEvent",
            "CustomerIdString": "11111111111111111111111111111111",
            "Tactic": "Malware",
            "SensorId": "00000000000000000000000000000000",
            "eid": 118,
            "PatternDispositionFlags": '{\n  "BlockingUnsupportedOrDisabled": false,\n  "BootupSafeguardEnabled": false,\n  "CriticalProcessDisabled": false,\n  "Detect": false,\n  "FsOperationBlocked": false,\n  "HandleOperationDowngraded": false,\n  "InddetMask": false,\n  "Indicator": false,\n  "KillActionFailed": false,\n  "KillParent": false,\n  "KillProcess": false,\n  "KillSubProcess": false,\n  "OperationBlocked": false,\n  "PolicyDisabled": false,\n  "ProcessBlocked": true,\n  "QuarantineFile": true,\n  "QuarantineMachine": false,\n  "RegistryOperationBlocked": false,\n  "Rooting": false,\n  "SensorOnly": false,\n  "SuspendParent": false,\n  "SuspendProcess": false\n}',
        },
    ),
    RuleTest(
        name="Low Severity Finding (FDREvent)",
        expected_result=True,
        log={
            "aid": "fa6a04a7f18d473fa06771b4961aa3d9",
            "cid": "712bcd164963442ea43d52917cecdecc",
            "ComputerName": "hostname.lan",
            "event": {
                "AgentIdString": "fa6a04a7f18d473fa06771b4961aa3d9",
                "CommandLine": "/bin/echo CROWDSTRIKE_SAMPLE_DETECTION",
                "ComputerName": "hostname.lan",
                "CustomerIdString": "712bcd164963442ea43d52917cecdecc",
                "DetectDescription": "Non-malicious sample detection generated for evaluation purposes.",
                "DetectId": "ldt:fa6a04a7f18d473fa06771b4961aa3d9:346037607921826886",
                "DetectName": "Suspicious Activity",
                "EventType": "Event_ExternalApiEvent",
                "EventUUID": "4624ba0c46c8405ea4998a0df7a5fa53",
                "ExternalApiType": "Event_DetectionSummaryEvent",
                "FalconHostLink": "https://falcon.us-2.crowdstrike.com/activity/detections/detail/00000000000000000000000000000000/222222222222222222?",
                "FileName": "echo",
                "FilePath": "/bin/",
                "GrandparentCommandLine": "-bash",
                "GrandparentImageFileName": "/bin/bash",
                "LocalIP": "192.168.86.255",
                "MACAddress": "a4-83-e7-19-28-8b",
                "MD5String": "2153a89b0a91c38f152acbefafd69b99",
                "MachineDomain": "",
                "Nonce": 1,
                "Objective": "N/A",
                "OriginSourceIpAddress": "",
                "ParentCommandLine": "bash",
                "ParentImageFileName": "/bin/bash",
                "ParentProcessId": 346017374056168100,
                "PatternDispositionDescription": "Detection, standard detection.",
                "PatternDispositionFlags": {
                    "BootupSafeguardEnabled": False,
                    "CriticalProcessDisabled": False,
                    "Detect": False,
                    "FsOperationBlocked": False,
                    "InddetMask": False,
                    "Indicator": False,
                    "KillParent": False,
                    "KillProcess": False,
                    "KillSubProcess": False,
                    "OperationBlocked": False,
                    "PolicyDisabled": False,
                    "ProcessBlocked": False,
                    "QuarantineFile": False,
                    "QuarantineMachine": False,
                    "RegistryOperationBlocked": False,
                    "Rooting": False,
                    "SensorOnly": False,
                },
                "PatternDispositionValue": 0,
                "ProcessEndTime": 1616609989,
                "ProcessId": 346037607908199600,
                "ProcessStartTime": 1616609989,
                "SHA1String": "0000000000000000000000000000000000000000",
                "SHA256String": "9e8a9e9f8cab6f07d8e711043bf856893660143aaf4385cb4e7b6faa97d6e61e",
                "SensorId": "fa6a04a7f18d473fa06771b4961aa3d9",
                "Severity": 2,
                "SeverityName": "Low",
                "Tactic": "N/A",
                "Technique": "N/A",
                "UTCTimestamp": 1616609989000,
                "UserName": "username",
                "cid": "712bcd164963442ea43d52917cecdecc",
                "eid": 118,
                "timestamp": "2021-03-24T18:19:49Z",
            },
            "fdr_event_type": "Event_DetectionSummaryEvent",
            "p_any_domain_names": ["hostname.lan"],
            "p_any_md5_hashes": [
                "2153a89b0a91c38f152acbefafd69b99",
                "712bcd164963442ea43d52917cecdecc",
                "fa6a04a7f18d473fa06771b4961aa3d9",
            ],
            "p_any_sha1_hashes": ["0000000000000000000000000000000000000000"],
            "p_any_sha256_hashes": ["9e8a9e9f8cab6f07d8e711043bf856893660143aaf4385cb4e7b6faa97d6e61e"],
            "p_any_trace_ids": ["712bcd164963442ea43d52917cecdecc", "fa6a04a7f18d473fa06771b4961aa3d9"],
            "p_any_usernames": ["russ"],
            "p_event_time": "2021-03-24 18:19:49",
            "p_log_type": "Crowdstrike.FDREvent",
            "p_parse_time": "2023-01-25 13:56:51.82",
            "p_row_id": "be33cdd7f1bfdba6f483df811601",
            "p_schema_version": 0,
            "timestamp": "2021-03-24 18:19:49",
        },
    ),
    RuleTest(
        name="Non-match (FDREvent)",
        expected_result=False,
        log={
            "cid": "11111111111111111111111111111111",
            "CommandLine": "/Applications/app.app/Contents/MacOS/pup app",
            "Objective": "Falcon Detection Method",
            "Nonce": 1,
            "SHA256String": "3333333333333333333333333333333333333333333333333333333333333333",
            "event": {"ExternalApiType": "something else"},
            "fdr_event_type": "something else",
            "PatternDispositionValue": 2176,
            "Severity": 2,
            "PatternDispositionDescription": "Prevention/Quarantine, process was blocked from execution and quarantine was attempted.",
            "SeverityName": "Low",
            "MD5String": "33333333333333333333333333333333",
            "eid": 118,
        },
    ),
]


@panther_managed
class CrowdstrikeDetectionpassthrough(Rule):
    id = "Crowdstrike.Detection.passthrough-prototype"
    display_name = "Crowdstrike Detection Passthrough"
    default_severity = Severity.MEDIUM
    log_types = [LogType.CROWDSTRIKE_DETECTION_SUMMARY, LogType.CROWDSTRIKE_FDR_EVENT]
    tags = ["Crowdstrike"]
    default_description = "Crowdstrike Falcon has detected malicious activity on a host."
    default_runbook = "Follow the Falcon console link and follow the IR process as needed."
    default_reference = "https://www.crowdstrike.com/blog/tech-center/hunt-threat-activity-falcon-endpoint-protection/"
    dedup_period_minutes = 0
    summary_attributes = ["p_any_ip_addresses"]
    tests = crowdstrike_detectionpassthrough_tests

    def rule(self, event):
        return get_crowdstrike_field(event, "ExternalApiType", default="none") == "Event_DetectionSummaryEvent"

    def title(self, event):
        return (
            f"Crowdstrike Alert ({get_crowdstrike_field(event, 'Technique')}) - "
            + f"{get_crowdstrike_field(event, 'ComputerName')}"
            + f"({get_crowdstrike_field(event, 'UserName')})"
        )

    def alert_context(self, event):
        return crowdstrike_detection_alert_context(event)

    def severity(self, event):
        return get_crowdstrike_field(event, "SeverityName")

    def dedup(self, event):
        return f"{get_crowdstrike_field(event, 'EventUUID')} " + f"- {get_crowdstrike_field(event, 'ComputerName')}"
