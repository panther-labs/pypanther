from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class PushSecurityNewAppDetected(Rule):
    id = "Push.Security.New.App.Detected-prototype"
    display_name = "Push Security New App Detected"
    log_types = [LogType.PUSH_SECURITY_ENTITIES]
    default_severity = Severity.INFO

    def rule(self, event):
        if event.get("object") != "APP":
            return False
        if event.get("type") == "CREATE":
            return True
        return False

    def title(self, event):
        new_type = event.deep_get("new", "type")
        return f"New app in use: {new_type}"

    tests = [
        RuleTest(
            name="New App",
            expected_result=True,
            log={
                "id": "c478966c-f927-411c-b919-179832d3d50c",
                "new": {
                    "approvalStatus": None,
                    "creationTimestamp": 1698064423.0,
                    "id": "2a2197de-ad2c-47e4-8dcb-fb0f04cf83e0",
                    "notes": "",
                    "ownerId": None,
                    "sensitivityLevel": None,
                    "type": "ZAPIER",
                },
                "object": "APP",
                "old": None,
                "timestamp": 1698604061.0,
                "type": "CREATE",
                "version": "1",
            },
        ),
        RuleTest(
            name="App Updated",
            expected_result=False,
            log={
                "id": "c478966c-f927-411c-b919-179832d3d50c",
                "new": {
                    "approvalStatus": "APPROVED",
                    "creationTimestamp": 1698064423.0,
                    "id": "2a2197de-ad2c-47e4-8dcb-fb0f04cf83e0",
                    "notes": "Last security audit: 16 January 2023.\n",
                    "ownerId": "87569da6-fb7a-4df7-8ce2-246c14044911",
                    "sensitivityLevel": "HIGH",
                    "type": "ZAPIER",
                },
                "object": "APP",
                "old": {
                    "approvalStatus": "UNDER_REVIEW",
                    "creationTimestamp": 1698064423.0,
                    "id": "2a2197de-ad2c-47e4-8dcb-fb0f04cf83e0",
                    "notes": "Initial submission for review.\n",
                    "ownerId": "87569da6-fb7a-4df7-8ce2-246c14044911",
                    "sensitivityLevel": "MEDIUM",
                    "type": "ZAPIER",
                },
                "timestamp": 1698604061.0,
                "type": "UPDATE",
                "version": "1",
            },
        ),
    ]
