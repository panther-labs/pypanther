from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get, get_val_from_list

okta_password_access_tests: list[RuleTest] = [
    RuleTest(
        name="User accessed their own password",
        expected_result=False,
        log={
            "actor": {
                "alternateId": "eric.montgomery@email.com",
                "displayName": "Eric Montgomery",
                "id": "XXXXXXXXXXXXXXXX",
                "type": "User",
            },
            "authenticationContext": {"authenticationStep": 0, "externalSessionId": "XXXXXXXXXXXXXXXXX"},
            "client": {
                "device": "Mobile",
                "geographicalContext": {
                    "country": "Iceland",
                    "geolocation": {"lat": 81.09596, "lon": -10.30578},
                    "state": "Colorado",
                },
                "ipAddress": "218.56.201.220",
                "userAgent": {
                    "browser": "CHROME",
                    "os": "Android 1.x",
                    "rawUserAgent": "Mozilla/5.0 (Linux; Android 11; ONEPLUS A6013) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Mobile Safari/537.36",
                },
                "zone": "null",
            },
            "debugContext": {"debugData": ""},
            "eventType": "application.user_membership.show_password",
            "legacyEventType": "app.generic.show.password",
            "outcome": {"result": "SUCCESS"},
            "p_any_domain_names": ["."],
            "p_any_emails": ["eric.montgomery@email.com"],
            "p_any_ip_addresses": ["218.56.201.220"],
            "p_log_type": "Okta.SystemLog",
            "published": "2022-09-09 04:26:09.792",
            "request": {
                "ipChain": [
                    {
                        "geographicalContext": {
                            "country": "Iceland",
                            "geolocation": {"lat": 81.0959, "lon": -104.9868},
                        },
                        "ip": "218.56.201.220",
                        "version": "V4",
                    },
                ],
            },
            "securityContext": {
                "asNumber": 940252,
                "asOrg": "t-mobile",
                "domain": ".",
                "isProxy": False,
                "isp": "t-mobile usa  inc.",
            },
            "severity": "INFO",
            "target": [
                {
                    "alternateId": "eric.montgomery@email.com",
                    "displayName": "Eric Montgomery",
                    "id": "16442344346b2385",
                    "type": "AppUser",
                },
                {
                    "alternateId": "Application2",
                    "displayName": "Application2",
                    "id": "16442ew83428795",
                    "type": "AppInstance",
                },
                {
                    "alternateId": "eric.montgomery@email.com",
                    "displayName": "Eric Montgomery",
                    "id": "16325kd349753",
                    "type": "User",
                },
            ],
            "transaction": {"detail": {}, "id": "XXXXXXXXXXXXXXXX", "type": "WEB"},
            "uuid": "XXXXXXXXXXXXXXXX",
            "version": "0",
        },
    ),
    RuleTest(
        name="User accessed another user's password",
        expected_result=True,
        log={
            "actor": {
                "alternateId": "eric.montgomery@email.com",
                "displayName": "Eric Montgomery",
                "id": "XXXXXXXXXXXXXXXX",
                "type": "User",
            },
            "authenticationContext": {"authenticationStep": 0, "externalSessionId": "XXXXXXXXXXXXXXXXX"},
            "client": {
                "device": "Mobile",
                "geographicalContext": {
                    "country": "Iceland",
                    "geolocation": {"lat": 81.0959, "lon": -10.30578},
                    "state": "Colorado",
                },
                "ipAddress": "218.56.201.220",
                "userAgent": {
                    "browser": "CHROME",
                    "os": "Android 1.x",
                    "rawUserAgent": "Mozilla/5.0 (Linux; Android 11; ONEPLUS A6013) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Mobile Safari/537.36",
                },
                "zone": "null",
            },
            "debugContext": {"debugData": ""},
            "eventType": "application.user_membership.show_password",
            "legacyEventType": "app.generic.show.password",
            "outcome": {"result": "SUCCESS"},
            "p_any_domain_names": ["."],
            "p_any_emails": ["eric.montgomery@email.com"],
            "p_any_ip_addresses": ["218.56.201.220"],
            "p_log_type": "Okta.SystemLog",
            "published": "2022-09-09 04:26:09.792",
            "request": {
                "ipChain": [
                    {
                        "geographicalContext": {
                            "country": "Iceland",
                            "geolocation": {"lat": 81.09596, "lon": -10.30578},
                        },
                        "ip": "218.56.201.220",
                        "version": "V4",
                    },
                ],
            },
            "securityContext": {
                "asNumber": 124526,
                "asOrg": "t-mobile",
                "domain": ".",
                "isProxy": False,
                "isp": "t-mobile usa  inc.",
            },
            "severity": "INFO",
            "target": [
                {
                    "alternateId": "vanessajohns@email.com",
                    "displayName": "Vanessa Johns",
                    "id": "0uat6tr9otyvdJbBM696",
                    "type": "AppUser",
                },
                {
                    "alternateId": "Application3",
                    "displayName": "Application3",
                    "id": "0oas6wl204Dn3gG5D696",
                    "type": "AppInstance",
                },
                {
                    "alternateId": "vanessajohns@email.com",
                    "displayName": "Vanessa Johns",
                    "id": "XXXXXXXXXXXXXXXX",
                    "type": "User",
                },
            ],
            "transaction": {"detail": {}, "id": "XXXXXXXXXXXXXXXX", "type": "WEB"},
            "uuid": "XXXXXXXXXXXXXXXX",
            "version": "0",
        },
    ),
    RuleTest(
        name="User accessed their own password - 2",
        expected_result=False,
        log={
            "actor": {
                "alternateId": "john.doe@emaildomain.com",
                "displayName": "John Doe",
                "id": "00u3nwfjxxxxxxxxxxxx",
                "type": "User",
            },
            "authenticationContext": {"authenticationStep": 0, "externalSessionId": "XXXXXXXXXXXXXXXXX"},
            "client": {
                "device": "Mobile",
                "geographicalContext": {
                    "country": "Iceland",
                    "geolocation": {"lat": 81.09596, "lon": -10.30578},
                    "state": "Colorado",
                },
                "ipAddress": "218.56.201.220",
                "userAgent": {
                    "browser": "CHROME",
                    "os": "Android 1.x",
                    "rawUserAgent": "Mozilla/5.0 (Linux; Android 11; ONEPLUS A6013) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Mobile Safari/537.36",
                },
                "zone": "null",
            },
            "debugContext": {"debugData": ""},
            "eventType": "application.user_membership.show_password",
            "legacyEventType": "app.generic.show.password",
            "outcome": {"result": "SUCCESS"},
            "published": "2024-03-27 13:17:41.835000000",
            "severity": "INFO",
            "securityContext": {
                "asNumber": 940252,
                "asOrg": "t-mobile",
                "domain": ".",
                "isProxy": False,
                "isp": "t-mobile usa  inc.",
            },
            "target": [
                {"alternateId": "John Doe", "displayName": "John Doe", "id": "00u3nwfjxxxxxxxxxxxx", "type": "AppUser"},
                {
                    "alternateId": "Software",
                    "displayName": "On The Fly App",
                    "id": "11u3nwfjxxxxxxxxxxxx",
                    "type": "AppInstance",
                },
                {
                    "alternateId": "john.doe@emaildomain.com",
                    "displayName": "John Doe",
                    "id": "00u3nwfjxxxxxxxxxxxx",
                    "type": "User",
                },
            ],
            "transaction": {"detail": {}, "id": "XXXXXXXXXXXXXXXX", "type": "WEB"},
            "uuid": "XXXXXXXXXXXXXXXX",
            "version": "0",
        },
    ),
]


@panther_managed
class OktaPasswordAccess(Rule):
    id = "Okta.PasswordAccess-prototype"
    display_name = "Okta Password Accessed"
    log_types = [LogType.OKTA_SYSTEM_LOG]
    tags = ["Okta", "Credential Access:Unsecured Credentials"]
    reports = {"MITRE ATT&CK": ["TA0006:T1552"]}
    default_severity = Severity.MEDIUM
    default_description = "User accessed another user's application password\n"
    default_reference = "https://help.okta.com/en-us/content/topics/apps/apps_revealing_the_password.htm"
    default_runbook = "Investigate whether this was authorized access.\n"
    tests = okta_password_access_tests

    def rule(self, event):
        if event.get("eventType") != "application.user_membership.show_password":
            return False
        # event['target'] = [{...}, {...}, {...}]
        self.TARGET_USERS = get_val_from_list(event.get("target", [{}]), "alternateId", "type", "User")
        self.TARGET_APP_NAMES = get_val_from_list(event.get("target", [{}]), "alternateId", "type", "AppInstance")
        if deep_get(event, "actor", "alternateId") not in self.TARGET_USERS:
            return True
        return False

    def dedup(self, event):
        dedup_str = deep_get(event, "actor", "alternateId")
        if self.TARGET_USERS:
            dedup_str += ":" + str(self.TARGET_USERS)
        if self.TARGET_APP_NAMES:
            dedup_str += ":" + str(self.TARGET_APP_NAMES)
        return dedup_str or ""

    def title(self, event):
        return f"A user {deep_get(event, 'actor', 'alternateId')} accessed another user's {self.TARGET_USERS} {self.TARGET_APP_NAMES} password"
