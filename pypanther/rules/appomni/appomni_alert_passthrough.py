from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class AppOmniAlertPassthrough(Rule):
    id = "AppOmni.Alert.Passthrough-prototype"
    display_name = "AppOmni Alert Passthrough"
    log_types = [LogType.APPOMNI_ALERTS]
    default_severity = Severity.MEDIUM
    reports = {
        "MITRE ATT&CK": [
            "TA0001:T1566",
            "TA0001:T1528",
            "TA0001:T1190",
            "TA0001:T1078",
            "TA0001:T1199",
            "TA0004:T1548",
            "TA0005:T1562",
            "TA0005:T1090",
            "TA0005:T1564",
            "TA0005:T1556",
            "TA0005:T1550",
            "TA0005:T1078",
            "TA0006:T1110",
            "TA0006:T1111",
            "TA0006:T1550",
            "TA0006:T1528",
            "TA0006:T1552",
            "TA0006:T1539",
            "TA0040:T1486",
            "TA0040:T1565",
            "TA0040:T1485",
            "TA0040:T1531",
            "TA0002:T1204",
            "TA0003:T1114",
            "TA0003:T1098",
            "TA0003:T1556",
            "TA0003:T1078",
            "TA0003:T1136",
            "TA0004:T1484",
            "TA0007:T1518",
            "TA0007:T1087",
            "TA0008:T1550",
            "TA0042:T1608",
            "TA0009:T1530",
            "TA0009:T1213",
            "TA0009:T1114",
            "TA0004:T1078",
            "TA0010:T1537",
            "TA0010:T1567",
        ],
    }
    SEV_DICT = {0: "Critical", 1: "High", 2: "Medium", 3: "Low", 4: "Info"}

    def rule(self, event):
        # Only alert where event.kind == "alert"
        if event.deep_get("event", "kind") == "alert":
            return True
        return False

    def title(self, event):
        # Create title that includes severity and message
        sev = self.SEV_DICT.get(event.deep_get("event", "severity"))
        # Use type service in title if only one field, label as 'Multiple Services' if more than one.
        if len(event.deep_get("related", "services", "type", default=[])) == 1:
            service = event.deep_get("related", "services", "type")[0]
        else:
            service = "Multiple Services"
        return f"[{sev}] - {service} - {event.get('message')}"

    def severity(self, event):
        # Update Panther alert severity based on severity from AppOmni Alert
        return self.SEV_DICT[event.deep_get("event", "severity", default=4)]

    def dedup(self, event):
        # Dedup by the events alert id, make sure we alert each time a new AppOmni alert is logged
        return f"Event ID: {event.deep_get('appomni', 'event', 'id')}"

    def alert_context(self, event):
        # 'Threat' and 'related' data to be included in the alert sent to the alert destination
        return {"threat": event.deep_get("rule", "threat"), "related": event.get("related")}

    tests = [
        RuleTest(
            name="Alert Type Severity 2",
            expected_result=True,
            log={
                "appomni": {
                    "alert": {"channel": "prod"},
                    "event": {
                        "dataset": "appomni_alert",
                        "id": "2ae1e281-4df1-5d26-81e2-7b75589e5dd4",
                        "sortable_event_id": "01HQ6JKJ5VE68CAT71JM27Z1D2",
                        "sortable_ingest_id": "01HQ6KGT23SN874A9ATHZCM1JH",
                    },
                    "organization": {"id": 285},
                },
                "event": {"created": "2024-02-21T19:50:42.499Z", "kind": "alert", "severity": 2},
                "message": "Security issue detected in GitHub repository 'appomni/ao_factory_interfaces'",
                "related": {
                    "event": ["cf8e782f-1657-5a4e-bdc2-cff1d147c912"],
                    "services": {"id": [12477], "type": ["github"]},
                },
                "rule": {
                    "name": "Repository Security Issue Detected",
                    "ruleset": "1423ff39-3250-4d53-aafb-142e740668bd",
                    "threat": {
                        "framework": "MITRE ATT&CK",
                        "tactic": {"id": ["TA0001"], "name": ["Initial Access"]},
                        "technique": {"id": ["T1195"], "name": ["Supply Chain Compromise"]},
                    },
                    "uuid": "6d873f19-4847-4412-9b70-6dca598ee64c",
                    "version": "1",
                },
                "timestamp": "2024-02-21T19:34:44.155Z",
                "version": "2.0.0",
            },
        ),
        RuleTest(
            name="Event Type",
            expected_result=False,
            log={
                "appomni": {
                    "event": {
                        "collected_time": "2024-02-28T19:53:34.266Z",
                        "dataset": "ao_auditlogs",
                        "id": "e4431a54-e57d-5cab-8b24-af194d49ebec",
                        "ingestion_time": "2024-02-28T19:53:34.298Z",
                    },
                    "organization": {"id": 6},
                    "service": {"account_id": "6", "id": 0, "name": "AppOmni", "type": "appomni"},
                },
                "event": {
                    "action": "update_token",
                    "category": ["authentication"],
                    "code": "access_token_refreshed_refreshtoken",
                    "created": "2024-02-28T19:53:34.266Z",
                    "dataset": "ao_auditlogs",
                    "id": "b90b4447-ae6a-4257-95fe-a3f9c5577158",
                    "ingested": "2024-02-28T19:53:34.298Z",
                    "kind": "event",
                    "module": "appomni",
                    "original": '{"action_at":"2024-02-28T19:53:34.256900+00:00","action_data":{"md_kind":"core.aoaudit.auditdata","md_version":1},"action_type":"access_token_refreshed_refreshtoken","log_id":"b90b4447-ae6a-4257-95fe-a3f9c5577158","org_id":6,"perspective_id":1487,"service_id":34,"service_type":"workday"}',
                    "type": ["change"],
                },
                "timestamp": "2024-02-28T19:53:34.256Z",
                "version": "2.0.0",
            },
        ),
        RuleTest(
            name="External App Install - Severity 3",
            expected_result=True,
            log={
                "@timestamp": "2024-02-26T18:02:09.044Z",
                "appomni": {
                    "alert": {"channel": "prod"},
                    "event": {
                        "dataset": "appomni_alert",
                        "id": "e927e832-bfb1-55d7-9159-0e5cd84dcc65",
                        "sortable_event_id": "01HQK99M8MZKWGZG24B5WV4JDK",
                        "sortable_ingest_id": "01HQK9DFC5DS5MYM0YEFFW7PF8",
                    },
                    "organization": {"id": 6},
                },
                "event": {"created": "2024-02-26T18:04:15.109Z", "kind": "alert", "severity": 3},
                "message": "An external application has been installed by appomni_int_justinz in Workday",
                "related": {
                    "event": ["cb786453-a105-5438-97a6-903d15e0cb7e"],
                    "ip": ["71.218.228.62"],
                    "services": {"id": [34], "type": ["workday"]},
                    "user": ["appomni_int_justinz"],
                },
                "rule": {
                    "name": "External Application Installed",
                    "ruleset": "1423ff39-3250-4d53-aafb-142e740668bd",
                    "threat": {
                        "framework": "MITRE ATT&CK",
                        "tactic": {
                            "id": ["TA0005", "TA0008", "TA0010"],
                            "name": ["Defense Evasion", "Lateral Movement", "Exfiltration"],
                        },
                        "technique": {
                            "id": ["T1550", "T1550", "T1567"],
                            "name": [
                                "Use Alternate Authentication Material",
                                "Use Alternate Authentication Material",
                                "Exfiltration Over Web Service",
                            ],
                        },
                    },
                    "uuid": "2aadaafd-4ec5-4a09-be6e-c2d70b555d19",
                    "version": "1",
                },
                "version": "2.0.0",
            },
        ),
        RuleTest(
            name="Multiple Services",
            expected_result=True,
            log={
                "appomni": {
                    "alert": {"channel": "prod"},
                    "event": {
                        "dataset": "appomni_alert",
                        "id": "2ae1e281-4df1-5d26-81e2-7b75589e5dd4",
                        "sortable_event_id": "01HQ6JKJ5VE68CAT71JM27Z1D2",
                        "sortable_ingest_id": "01HQ6KGT23SN874A9ATHZCM1JH",
                    },
                    "organization": {"id": 285},
                },
                "event": {"created": "2024-02-21T19:50:42.499Z", "kind": "alert", "severity": 2},
                "message": "Security issue detected in GitHub repository 'appomni/ao_factory_interfaces'",
                "related": {
                    "event": ["cf8e782f-1657-5a4e-bdc2-cff1d147c912"],
                    "services": {"id": [12477], "type": ["github", "workday"]},
                },
                "rule": {
                    "name": "Repository Security Issue Detected",
                    "ruleset": "1423ff39-3250-4d53-aafb-142e740668bd",
                    "threat": {
                        "framework": "MITRE ATT&CK",
                        "tactic": {"id": ["TA0001"], "name": ["Initial Access"]},
                        "technique": {"id": ["T1195"], "name": ["Supply Chain Compromise"]},
                    },
                    "uuid": "6d873f19-4847-4412-9b70-6dca598ee64c",
                    "version": "1",
                },
                "timestamp": "2024-02-21T19:34:44.155Z",
                "version": "2.0.0",
            },
        ),
    ]
