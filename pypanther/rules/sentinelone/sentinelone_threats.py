from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class SentinelOneThreats(Rule):
    default_description = "Passthrough SentinelOne Threats "
    display_name = "SentinelOne Threats"
    default_reference = "https://www.sentinelone.com/blog/feature-spotlight-introducing-the-new-threat-center/"
    default_severity = Severity.HIGH
    log_types = [LogType.SENTINELONE_ACTIVITY]
    id = "SentinelOne.Threats-prototype"  # New Malicious Threat Not Mitigated
    # New Malicious Threat Not Mitigated
    # New Suspicious Threat Not Mitigated
    # New Suspicious Threat Not Mitigated
    NEW_THREAT_ACTIVITYTYPES = [19, 4108, 4003, 4109]

    def rule(self, event):
        return event.get("activitytype") in self.NEW_THREAT_ACTIVITYTYPES

    def title(self, event):
        return f"SentinelOne - [{event.deep_get('data', 'confidencelevel', default='')}] level [{event.deep_get('data', 'threatclassification', default='')}] threat detected from [{event.deep_get('data', 'threatclassificationsource', default='')}]."

    def dedup(self, event):
        return f"s1threat:{event.get('id', '')}"

    def severity(self, event):
        if event.deep_get("data", "confidencelevel", default="") == "malicious":
            return "CRITICAL"
        return "HIGH"

    def alert_context(self, event):
        return {
            "primarydescription": event.get("primarydescription", ""),
            "accountname": event.get("accountname", ""),
            "accountid": event.get("accountid", ""),
            "siteid": event.get("siteid", ""),
            "sitename": event.get("sitename", ""),
            "threatid": event.get("threatid", ""),
            "groupid": event.get("groupid", ""),
            "groupname": event.get("groupname", ""),
            "activityuuid": event.get("activityuuid", ""),
            "agentid": event.get("agentid", ""),
            "id": event.get("id", ""),
            "data": event.get("data", {}),
        }

    tests = [
        RuleTest(
            name="malicious event",
            expected_result=True,
            log={
                "accountid": "123456789",
                "accountname": "Account1",
                "activitytype": 19,
                "activityuuid": "123-456-678-89",
                "agentid": "1111112222233333",
                "createdat": "2022-12-07 16:08:55.703",
                "data": {
                    "accountname": "Account1",
                    "computername": "BobsPC",
                    "confidencelevel": "malicious",
                    "filecontenthash": "cf8bd9dfddff007f75adf4c2be48005cea317c62",
                    "filedisplayname": "eicar.txt",
                    "filepath": "/home/ubuntu/eicar.txt",
                    "fullscopedetails": "Group Testing in Site Default site of Account Account1",
                    "fullscopedetailspath": "Global / Account1 / Default site / Testing",
                    "groupname": "Testing",
                    "sitename": "Default site",
                    "threatclassification": "Virus",
                    "threatclassificationsource": "Cloud",
                },
                "groupid": "12345",
                "groupname": "Testing",
                "id": "11111111",
                "primarydescription": "Threat with confidence level malicious detected: eicar.txt",
                "secondarydescription": "cf8bd9dfddff007f75adf4c2be48005cea317c62",
                "siteid": "456789",
                "sitename": "Default site",
                "threatid": "123456789",
                "updatedat": "2022-12-07 16:08:55.698",
            },
        ),
        RuleTest(
            name="non-threat event",
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
        RuleTest(
            name="suspicious event",
            expected_result=True,
            log={
                "accountid": "123456789",
                "accountname": "Account1",
                "activitytype": 19,
                "activityuuid": "123-456-678-89",
                "agentid": "1111112222233333",
                "createdat": "2022-12-07 16:08:55.703",
                "data": {
                    "accountname": "Account1",
                    "computername": "BobsPC",
                    "confidencelevel": "suspicious",
                    "filecontenthash": "cf8bd9dfddff007f75adf4c2be48005cea317c62",
                    "filedisplayname": "eicar.txt",
                    "filepath": "/home/ubuntu/eicar.txt",
                    "fullscopedetails": "Group Testing in Site Default site of Account Account1",
                    "fullscopedetailspath": "Global / Account1 / Default site / Testing",
                    "groupname": "Testing",
                    "sitename": "Default site",
                    "threatclassification": "Virus",
                    "threatclassificationsource": "Cloud",
                },
                "groupid": "12345",
                "groupname": "Testing",
                "id": "11111111",
                "primarydescription": "Threat with confidence level malicious detected: eicar.txt",
                "secondarydescription": "cf8bd9dfddff007f75adf4c2be48005cea317c62",
                "siteid": "456789",
                "sitename": "Default site",
                "threatid": "123456789",
                "updatedat": "2022-12-07 16:08:55.698",
            },
        ),
    ]
