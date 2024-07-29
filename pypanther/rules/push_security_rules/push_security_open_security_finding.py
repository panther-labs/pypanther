from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

push_security_open_security_finding_tests: list[RuleTest] = [
    RuleTest(
        name="Resolved Finding",
        expected_result=False,
        log={
            "id": "c478966c-f927-411c-b919-179832d3d50c",
            "new": {
                "accountId": None,
                "appId": "2a2197de-ad2c-47e4-8dcb-fb0f04cf83e0",
                "appType": "PUSH_SECURITY",
                "creationTimestamp": 1698064423.0,
                "employeeId": "379ac7ea-ff2a-42ef-af37-06d2020dc46a",
                "id": "d6a32ba5-0532-4a66-8137-48cdf409c972",
                "passwordId": "c4a045a1-5331-4714-af83-6a361e98960d",
                "state": "RESOLVED",
                "type": "WEAK_PASSWORD",
            },
            "object": "FINDING",
            "old": {
                "accountId": None,
                "appId": "2a2197de-ad2c-47e4-8dcb-fb0f04cf83e0",
                "appType": "PUSH_SECURITY",
                "creationTimestamp": 1698064423.0,
                "employeeId": "379ac7ea-ff2a-42ef-af37-06d2020dc46a",
                "id": "d6a32ba5-0532-4a66-8137-48cdf409c972",
                "passwordId": "c4a045a1-5331-4714-af83-6a361e98960d",
                "state": "OPEN",
                "type": "WEAK_PASSWORD",
            },
            "timestamp": 1698604061.0,
            "type": "UPDATE",
            "version": "1",
        },
    ),
    RuleTest(
        name="New Finding",
        expected_result=True,
        log={
            "id": "c478966c-f927-411c-b919-179832d3d50c",
            "new": {
                "accountId": None,
                "appId": "2a2197de-ad2c-47e4-8dcb-fb0f04cf83e0",
                "appType": "PUSH_SECURITY",
                "creationTimestamp": 1698064423.0,
                "employeeId": "379ac7ea-ff2a-42ef-af37-06d2020dc46a",
                "id": "d6a32ba5-0532-4a66-8137-48cdf409c972",
                "passwordId": "c4a045a1-5331-4714-af83-6a361e98960d",
                "state": "OPEN",
                "type": "WEAK_PASSWORD",
            },
            "object": "FINDING",
            "old": None,
            "timestamp": 1698604061.0,
            "type": "CREATE",
            "version": "1",
        },
    ),
    RuleTest(
        name="Reopened Finding",
        expected_result=True,
        log={
            "id": "c478966c-f927-411c-b919-179832d3d50c",
            "new": {
                "accountId": None,
                "appId": "2a2197de-ad2c-47e4-8dcb-fb0f04cf83e0",
                "appType": "PUSH_SECURITY",
                "creationTimestamp": 1698064423.0,
                "employeeId": "379ac7ea-ff2a-42ef-af37-06d2020dc46a",
                "id": "d6a32ba5-0532-4a66-8137-48cdf409c972",
                "passwordId": "c4a045a1-5331-4714-af83-6a361e98960d",
                "state": "OPEN",
                "type": "WEAK_PASSWORD",
            },
            "object": "FINDING",
            "old": {
                "accountId": None,
                "appId": "2a2197de-ad2c-47e4-8dcb-fb0f04cf83e0",
                "appType": "PUSH_SECURITY",
                "creationTimestamp": 1698064423.0,
                "employeeId": "379ac7ea-ff2a-42ef-af37-06d2020dc46a",
                "id": "d6a32ba5-0532-4a66-8137-48cdf409c972",
                "passwordId": "c4a045a1-5331-4714-af83-6a361e98960d",
                "state": "RESOLVED",
                "type": "WEAK_PASSWORD",
            },
            "timestamp": 1698604061.0,
            "type": "UPDATE",
            "version": "1",
        },
    ),
]


@panther_managed
class PushSecurityOpenSecurityFinding(Rule):
    id = "Push.Security.Open.Security.Finding-prototype"
    display_name = "Push Security Open Security Finding"
    log_types = [LogType.PUSH_SECURITY_ENTITIES]
    default_severity = Severity.INFO
    tests = push_security_open_security_finding_tests

    def rule(self, event):
        if event.get("object") != "FINDING":
            return False
        event_type = event.get("type")
        if event_type == "CREATE":
            return True
        if event_type == "UPDATE" and event.deep_get("new", "state") == "OPEN":
            return True
        return False

    def title(self, event):
        new_type = event.deep_get("new", "type")
        app_type = event.deep_get("new", "appType")
        return f"Open finding {new_type} for app {app_type}"
