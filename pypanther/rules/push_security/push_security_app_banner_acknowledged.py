from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class PushSecurityAppBannerAcknowledged(Rule):
    id = "Push.Security.App.Banner.Acknowledged-prototype"
    display_name = "Push Security App Banner Acknowledged"
    log_types = [LogType.PUSH_SECURITY_ACTIVITY]
    default_severity = Severity.LOW

    def rule(self, event):
        if event.get("object") != "APP_BANNER":
            return False
        if event.deep_get("new", "action") == "ACKNOWLEDGED":
            return True
        return False

    def title(self, event):
        app_type = event.deep_get("new", "appType")
        employee_email = event.deep_get("new", "employee", "email")
        return f"{app_type} accessed by {employee_email}"

    def alert_context(self, event):
        return {
            "Push Security app banner": event.deep_get("new", "appBanner", "mode"),
            "Title": event.deep_get("new", "appBanner", "title"),
            "Subtext": event.deep_get("new", "appBanner", "subtext"),
            "Button": event.deep_get("new", "appBanner", "buttonText"),
        }

    tests = [
        RuleTest(
            name="App Banner Acknowledged",
            expected_result=True,
            log={
                "id": "c478966c-f927-411c-b919-179832d3d50c",
                "new": {
                    "action": "ACKNOWLEDGED",
                    "appBanner": {
                        "buttonText": "Proceed anyway",
                        "mode": "ACKNOWLEDGE",
                        "subtext": "This app is not approved, please use Google Drive instead.",
                        "title": "This app is not approved for use",
                    },
                    "appType": "DROPBOX",
                    "browser": "CHROME",
                    "employee": {
                        "chatopsEnabled": True,
                        "creationTimestamp": 1698669223.0,
                        "department": "Security Engineering",
                        "email": "john.hill@example.com",
                        "firstName": "John",
                        "id": "2a2197de-ad2c-47e4-8dcb-fb0f04cf83e0",
                        "lastName": "Hill",
                        "licensed": True,
                        "location": "New York",
                    },
                    "os": "WINDOWS",
                    "sourceIpAddress": "8.158.25.38",
                    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299",
                },
                "object": "APP_BANNER",
                "timestamp": 1698604061.0,
                "version": "1",
            },
        ),
        RuleTest(
            name="App Banner Displayed",
            expected_result=False,
            log={
                "id": "c478966c-f927-411c-b919-179832d3d50c",
                "new": {
                    "action": "DISPLAYED",
                    "appBanner": {
                        "buttonText": "Proceed anyway",
                        "mode": "ACKNOWLEDGE",
                        "subtext": "This app is not approved, please use Google Drive instead.",
                        "title": "This app is not approved for use",
                    },
                    "appType": "DROPBOX",
                    "browser": "CHROME",
                    "employee": {
                        "chatopsEnabled": True,
                        "creationTimestamp": 1698669223.0,
                        "department": "Security Engineering",
                        "email": "john.hill@example.com",
                        "firstName": "John",
                        "id": "2a2197de-ad2c-47e4-8dcb-fb0f04cf83e0",
                        "lastName": "Hill",
                        "licensed": True,
                        "location": "New York",
                    },
                    "os": "WINDOWS",
                    "sourceIpAddress": "8.158.25.38",
                    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299",
                },
                "object": "APP_BANNER",
                "timestamp": 1698604061.0,
                "version": "1",
            },
        ),
        RuleTest(
            name="App Banner Inform Mode",
            expected_result=False,
            log={
                "id": "c478966c-f927-411c-b919-179832d3d50c",
                "new": {
                    "action": "DISPLAYED",
                    "appBanner": {
                        "buttonText": None,
                        "mode": "INFORM",
                        "subtext": "This app is not approved, please use Google Drive instead.",
                        "title": "This app is not approved for use",
                    },
                    "appType": "DROPBOX",
                    "browser": "CHROME",
                    "employee": {
                        "chatopsEnabled": True,
                        "creationTimestamp": 1698669223.0,
                        "department": "Security Engineering",
                        "email": "john.hill@example.com",
                        "firstName": "John",
                        "id": "2a2197de-ad2c-47e4-8dcb-fb0f04cf83e0",
                        "lastName": "Hill",
                        "licensed": True,
                        "location": "New York",
                    },
                    "os": "WINDOWS",
                    "sourceIpAddress": "8.158.25.38",
                    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299",
                },
                "object": "APP_BANNER",
                "timestamp": 1698604061.0,
                "version": "1",
            },
        ),
    ]
