from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class SentinelOneAlertPassthrough(Rule):
    default_description = "SentinelOne Alert Passthrough"
    display_name = "SentinelOne Alert Passthrough"
    default_reference = "https://www.sentinelone.com/blog/feature-spotlight-introducing-the-new-threat-center/"
    default_severity = Severity.HIGH
    log_types = [LogType.SENTINELONE_ACTIVITY]
    id = "SentinelOne.Alert.Passthrough-prototype"
    SENTINELONE_SEVERITY = {"E_LOW": "LOW", "E_MEDIUM": "MEDIUM", "E_HIGH": "HIGH", "E_CRITICAL": "CRITICAL"}

    def rule(self, event):
        # 3608 corresponds to new alerts
        return event.get("activitytype") == 3608

    def title(self, event):
        return f"SentinelOne [{self.SENTINELONE_SEVERITY.get(event.deep_get('data', 'severity', default=''))}] Alert - [{event.deep_get('data', 'rulename')}]"

    def dedup(self, event):
        return f"s1alerts:{event.get('id')}"

    def severity(self, event):
        return self.SENTINELONE_SEVERITY.get(event.deep_get("data", "severity", default=""), "MEDIUM")

    def alert_context(self, event):
        data_cleaned = {k: v for k, v in event.get("data", {}).items() if v != ""}
        return {
            "primarydescription": event.get("primarydescription", ""),
            "accountname": event.get("accountname", ""),
            "accountid": event.get("accountid", ""),
            "siteid": event.get("siteid", ""),
            "sitename": event.get("sitename", ""),
            "groupid": event.get("groupid", ""),
            "groupname": event.get("groupname", ""),
            "activityuuid": event.get("activityuuid", ""),
            "agentid": event.get("agentid", ""),
            "id": event.get("id", ""),
            "data": data_cleaned,
        }

    tests = [
        RuleTest(
            name="CRITICAL",
            expected_result=True,
            log={
                "accountid": "12345",
                "accountname": "Account1",
                "activitytype": 3608,
                "activityuuid": "f123-345-1234",
                "agentid": "1234567",
                "createdat": "2022-12-07 17:36:05.076",
                "data": {
                    "accountid": "987654",
                    "accountname": "Account1",
                    "actoralternateid": "",
                    "agentipv4": "1.2.3.4",
                    "alertid": "1570395776954206544",
                    "datasourcename": "SentinelOne",
                    "detectedat": "2022-12-07T17:35:48Z",
                    "dnsrequest": "",
                    "dnsresponse": "",
                    "dstip": "",
                    "dstport": 0,
                    "ruledescription": "test",
                    "ruleid": "12345",
                    "rulename": "test-rule",
                    "rulescopeid": 123,
                    "rulescopelevel": "E_ACCOUNT",
                    "scopeid": 123,
                    "scopelevel": "Group",
                    "scopename": "Default Group",
                    "severity": "E_CRITICAL",
                    "siteid": "12345",
                    "sitename": "Default site",
                    "tiindicatorsource": "",
                    "tiindicatortype": "",
                    "tiindicatorvalue": "",
                    "userid": 432134,
                },
                "groupid": "12345",
                "groupname": "Default Group",
                "id": "5423",
                "primarydescription": "Alert created for sshd from Custom Rule: test-rule in Group Default Group in Site Default site of Account Account1, detected on BobsPC.",
                "secondarydescription": "e020cd039b099b6bfdfd33d13554da5383cc4cc0",
                "siteid": "1408801957997975086",
                "sitename": "Default site",
                "updatedat": "2022-12-07 17:36:05.075",
                "userid": "1234",
            },
        ),
        RuleTest(
            name="MEDIUM",
            expected_result=True,
            log={
                "accountid": "12345",
                "accountname": "Account1",
                "activitytype": 3608,
                "activityuuid": "f123-345-1234",
                "agentid": "1234567",
                "createdat": "2022-12-07 17:36:05.076",
                "data": {
                    "accountid": "987654",
                    "accountname": "Account1",
                    "actoralternateid": "",
                    "agentipv4": "1.2.3.4",
                    "alertid": "1570395776954206544",
                    "datasourcename": "SentinelOne",
                    "detectedat": "2022-12-07T17:35:48Z",
                    "dnsrequest": "",
                    "dnsresponse": "",
                    "dstip": "",
                    "dstport": 0,
                    "ruledescription": "test",
                    "ruleid": "12345",
                    "rulename": "test-rule",
                    "rulescopeid": 123,
                    "rulescopelevel": "E_ACCOUNT",
                    "scopeid": 123,
                    "scopelevel": "Group",
                    "scopename": "Default Group",
                    "severity": "E_MEDIUM",
                    "siteid": "12345",
                    "sitename": "Default site",
                    "tiindicatorsource": "",
                    "tiindicatortype": "",
                    "tiindicatorvalue": "",
                    "userid": 432134,
                },
                "groupid": "12345",
                "groupname": "Default Group",
                "id": "5423",
                "primarydescription": "Alert created for sshd from Custom Rule: test-rule in Group Default Group in Site Default site of Account Account1, detected on BobsPC.",
                "secondarydescription": "e020cd039b099b6bfdfd33d13554da5383cc4cc0",
                "siteid": "1408801957997975086",
                "sitename": "Default site",
                "updatedat": "2022-12-07 17:36:05.075",
                "userid": "1234",
            },
        ),
        RuleTest(
            name="Non-Alert",
            expected_result=False,
            log={
                "accountid": "12345",
                "accountname": "Account1",
                "activitytype": 90,
                "activityuuid": "123-456-789",
                "agentid": "111111",
                "createdat": "2022-12-07 16:06:35.483",
                "data": {
                    "accountname": "Account1",
                    "computername": "BobsPC",
                    "createdat": "2022-12-07T16:06:35.477827Z",
                    "fullscopedetails": "Group Testing in Site Default site of Account Account1",
                    "fullscopedetailspath": "Global / Account1 / Default site / Testing",
                    "groupname": "Testing",
                    "scopelevel": "Group",
                    "scopename": "Testing",
                    "sitename": "Default site",
                    "status": "started",
                },
                "groupid": "11234",
                "groupname": "Testing",
                "id": "123564",
                "primarydescription": "Agent BobsPC started full disk scan at Wed, 07 Dec 2022, 16:06:35 UTC.",
                "siteid": "12345",
                "sitename": "Default site",
                "updatedat": "2022-12-07 16:06:35.479",
            },
        ),
    ]
