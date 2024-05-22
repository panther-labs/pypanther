from typing import List
from panther_analysis.base import PantherRule, PantherRuleTest, Severity, RuleMock
import json
import logging
import panther_analysis.helpers.panther_event_type_helpers as event_type
from panther_detection_helpers.caching import get_string_set, put_string_set
from panther_analysis.helpers.panther_oss_helpers import add_parse_delay, geoinfo_from_ip

standard_unusual_login_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="AWS.CloudTrail - Successful Login - New Geo - Exceeds History Length of 5",
        ExpectedResult=True,
        Mocks=[
            RuleMock(
                ObjectName="geoinfo_from_ip",
                ReturnValue='{ "region": "UnitTestRegion", "city": "UnitTestCityNew", "country": "UnitTestCountry", "hostname": "somedomain.com", "org": "Some Org" }',
            ),
            RuleMock(
                ObjectName="get_string_set",
                ReturnValue='{ "UnitTestRegion:UnitTestCity1": "2021-06-04 09:59:53.650801", "UnitTestRegion:UnitTestCity2": "2021-06-04 09:59:53.650802", "UnitTestRegion:UnitTestCity3": "2021-06-04 09:59:53.650803", "UnitTestRegion:UnitTestCity4": "2021-06-04 09:59:53.650804", "UnitTestRegion:UnitTestCity5": "2021-06-04 09:59:53.650805" }',
            ),
            RuleMock(ObjectName="put_string_set", ReturnValue=""),
        ],
        Log={
            "userIdentity": {"type": "IAMUser", "userName": "some_user"},
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "111.111.111.111",
            "responseElements": {"ConsoleLogin": "Success"},
            "p_parse_time": "2021-06-04 10:02:33.650807",
            "p_event_time": "2021-06-04 09:59:53.650807",
            "p_log_type": "AWS.CloudTrail",
        },
    ),
    PantherRuleTest(
        Name="AWS.CloudTrail - Successful Login - New Geo - Does Not Exceed History Length of 5",
        ExpectedResult=True,
        Mocks=[
            RuleMock(
                ObjectName="geoinfo_from_ip",
                ReturnValue='{ "region": "UnitTestRegion", "city": "UnitTestCityNew", "country": "UnitTestCountry" }',
            ),
            RuleMock(
                ObjectName="get_string_set",
                ReturnValue='{"UnitTestRegion:UnitTestCity": "2021-06-04 09:59:53.650801"}',
            ),
            RuleMock(ObjectName="put_string_set", ReturnValue=""),
        ],
        Log={
            "userIdentity": {"type": "IAMUser", "userName": "some_user"},
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "111.111.111.111",
            "responseElements": {"ConsoleLogin": "Success"},
            "p_parse_time": "2021-06-04 10:02:33.650807",
            "p_event_time": "2021-06-04 09:59:53.650807",
            "p_log_type": "AWS.CloudTrail",
        },
    ),
    PantherRuleTest(
        Name="AWS.CloudTrail - Successful Login - New Geo - No History",
        ExpectedResult=False,
        Mocks=[
            RuleMock(
                ObjectName="geoinfo_from_ip",
                ReturnValue='{ "region": "UnitTestRegion", "city": "UnitTestCityNew", "country": "UnitTestCountry" }',
            ),
            RuleMock(ObjectName="get_string_set", ReturnValue=""),
            RuleMock(ObjectName="put_string_set", ReturnValue=""),
        ],
        Log={
            "userIdentity": {"type": "IAMUser", "userName": "some_user"},
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "111.111.111.111",
            "responseElements": {"ConsoleLogin": "Success"},
            "p_parse_time": "2021-06-04 10:02:33.650807",
            "p_event_time": "2021-06-04 09:59:53.650807",
            "p_log_type": "AWS.CloudTrail",
        },
    ),
    PantherRuleTest(
        Name="AWS.CloudTrail - Successful Login - New Geo",
        ExpectedResult=True,
        Mocks=[
            RuleMock(
                ObjectName="geoinfo_from_ip",
                ReturnValue='{ "region": "UnitTestRegion", "city": "UnitTestCityNew", "country": "UnitTestCountry" }',
            ),
            RuleMock(
                ObjectName="get_string_set",
                ReturnValue='{"UnitTestRegion:UnitTestCity": "2021-06-04 09:59:53.650801"}',
            ),
            RuleMock(ObjectName="put_string_set", ReturnValue=""),
        ],
        Log={
            "userIdentity": {"type": "IAMUser", "userName": "some_user"},
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "111.111.111.111",
            "responseElements": {"ConsoleLogin": "Success"},
            "p_parse_time": "2021-06-04 10:02:33.650807",
            "p_event_time": "2021-06-04 09:59:53.650807",
            "p_log_type": "AWS.CloudTrail",
        },
    ),
    PantherRuleTest(
        Name="AWS.CloudTrail - Successful Login - Existing Geo",
        ExpectedResult=False,
        Mocks=[
            RuleMock(
                ObjectName="geoinfo_from_ip",
                ReturnValue='{ "region": "UnitTestRegion", "city": "UnitTestCity1", "country": "UnitTestCountry" }',
            ),
            RuleMock(
                ObjectName="get_string_set",
                ReturnValue='{ "UnitTestRegion:UnitTestCity1": "2021-06-04 09:59:53.650801", "UnitTestRegion:UnitTestCity2": "2021-06-04 09:59:53.650802", "UnitTestRegion:UnitTestCity3": "2021-06-04 09:59:53.650803", "UnitTestRegion:UnitTestCity4": "2021-06-04 09:59:53.650804", "UnitTestRegion:UnitTestCity5": "2021-06-04 09:59:53.650805" }',
            ),
            RuleMock(ObjectName="put_string_set", ReturnValue=""),
        ],
        Log={
            "userIdentity": {"type": "IAMUser", "userName": "some_user"},
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "111.111.111.111",
            "responseElements": {"ConsoleLogin": "Success"},
            "p_log_type": "AWS.CloudTrail",
        },
    ),
    PantherRuleTest(
        Name="AWS.CloudTrail - Failed Login",
        ExpectedResult=False,
        Log={
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "1111",
                "arn": "arn:aws:iam::123456789012:user/tester",
                "accountId": "123456789012",
                "userName": "tester",
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "Mozilla",
            "requestParameters": None,
            "responseElements": {"ConsoleLogin": "Failure"},
            "additionalEventData": {
                "LoginTo": "https://console.aws.amazon.com/console/",
                "MobileVersion": "No",
                "MFAUsed": "No",
            },
            "eventID": "1",
            "eventType": "AwsConsoleSignIn",
            "recipientAccountId": "123456789012",
            "p_event_time": "2021-06-04 09:59:53.650807",
            "p_log_type": "AWS.CloudTrail",
        },
    ),
    PantherRuleTest(
        Name="GSuite - New Geo - No History",
        ExpectedResult=False,
        Mocks=[
            RuleMock(
                ObjectName="geoinfo_from_ip",
                ReturnValue='{ "region": "UnitTestRegion", "city": "UnitTestCity1", "country": "UnitTestCountry" }',
            ),
            RuleMock(ObjectName="get_string_set", ReturnValue=""),
            RuleMock(ObjectName="put_string_set", ReturnValue=""),
        ],
        Log={
            "actor": {"email": "nick@acme.io", "profileId": "11949494222400014922"},
            "id": {"applicationName": "login"},
            "ipAddress": "111.111.111.111",
            "events": [{"type": "login", "name": "login_success"}],
            "p_parse_time": "2021-06-04 10:02:33.650807",
            "p_event_time": "2021-06-04 09:59:53.650807",
            "p_log_type": "GSuite.Reports",
        },
    ),
    PantherRuleTest(
        Name="GSuite - New Geo",
        ExpectedResult=True,
        Mocks=[
            RuleMock(
                ObjectName="geoinfo_from_ip",
                ReturnValue='{ "region": "UnitTestRegion", "city": "UnitTestCity1", "country": "UnitTestCountry" }',
            ),
            RuleMock(
                ObjectName="get_string_set",
                ReturnValue='{"UnitTestRegion:UnitTestCity": "2021-06-04 09:59:53.650801"}',
            ),
            RuleMock(ObjectName="put_string_set", ReturnValue=""),
        ],
        Log={
            "actor": {"email": "nick@acme.io", "profileId": "11949494222400014922"},
            "id": {"applicationName": "login"},
            "ipAddress": "111.111.111.111",
            "events": [{"type": "login", "name": "login_success"}],
            "p_parse_time": "2021-06-04 10:02:33.650807",
            "p_event_time": "2021-06-04 09:59:53.650807",
            "p_log_type": "GSuite.Reports",
        },
    ),
    PantherRuleTest(
        Name="Okta - Non Login",
        ExpectedResult=False,
        Log={"eventType": "logout", "p_log_type": "Okta.SystemLog"},
    ),
    PantherRuleTest(
        Name="Okta - Failed Login",
        ExpectedResult=False,
        Log={
            "actor": {
                "alternateId": "admin",
                "displayName": "unknown",
                "id": "unknown",
                "type": "User",
            },
            "client": {"ipAddress": "redacted"},
            "eventType": "user.session.start",
            "outcome": {"reason": "VERIFICATION_ERROR", "result": "FAILURE"},
            "p_log_type": "Okta.SystemLog",
        },
    ),
    PantherRuleTest(
        Name="OneLogin - Non Login",
        ExpectedResult=False,
        Log={"event_type_id": 8, "p_log_type": "OneLogin.Events"},
    ),
    PantherRuleTest(
        Name="Zendesk - Successful Login - No History",
        ExpectedResult=False,
        Mocks=[
            RuleMock(
                ObjectName="geoinfo_from_ip",
                ReturnValue='{ "region": "UnitTestRegion", "city": "UnitTestCity1", "country": "UnitTestCountry" }',
            ),
            RuleMock(ObjectName="get_string_set", ReturnValue=""),
            RuleMock(ObjectName="put_string_set", ReturnValue=""),
        ],
        Log={
            "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
            "id": 123456789123,
            "action_label": "Sign in",
            "actor_id": 123,
            "actor_name": "Bob Cat",
            "source_id": 123,
            "source_type": "user",
            "source_label": "Bob Cat",
            "action": "login",
            "change_description": "Successful sign-in using Zendesk password from https://myzendesk.zendesk.com/access/login",
            "ip_address": "127.0.0.1",
            "created_at": "2021-05-28T18:39:50Z",
            "p_log_type": "Zendesk.Audit",
            "p_parse_time": "2021-06-04 10:02:33.650807",
            "p_event_time": "2021-06-04 09:59:53.650807",
        },
    ),
    PantherRuleTest(
        Name="Zendesk - Successful Login",
        ExpectedResult=True,
        Mocks=[
            RuleMock(
                ObjectName="geoinfo_from_ip",
                ReturnValue='{ "region": "UnitTestRegion", "city": "UnitTestCity1", "country": "UnitTestCountry" }',
            ),
            RuleMock(
                ObjectName="get_string_set",
                ReturnValue='{"UnitTestRegion:UnitTestCity": "2021-06-04 09:59:53.650801"}',
            ),
            RuleMock(ObjectName="put_string_set", ReturnValue=""),
        ],
        Log={
            "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
            "id": 123456789123,
            "action_label": "Sign in",
            "actor_id": 123,
            "actor_name": "Bob Cat",
            "source_id": 123,
            "source_type": "user",
            "source_label": "Bob Cat",
            "action": "login",
            "change_description": "Successful sign-in using Zendesk password from https://myzendesk.zendesk.com/access/login",
            "ip_address": "127.0.0.1",
            "created_at": "2021-05-28T18:39:50Z",
            "p_log_type": "Zendesk.Audit",
            "p_parse_time": "2021-06-04 10:02:33.650807",
            "p_event_time": "2021-06-04 09:59:53.650807",
        },
    ),
    PantherRuleTest(
        Name="GSuite - Successful Login Event",
        ExpectedResult=True,
        Mocks=[
            RuleMock(
                ObjectName="geoinfo_from_ip",
                ReturnValue='{ "region": "UnitTestRegion", "city": "UnitTestCity1", "country": "UnitTestCountry" }',
            ),
            RuleMock(
                ObjectName="get_string_set",
                ReturnValue='{"UnitTestRegion:UnitTestCity": "2021-06-04 09:59:53.650801"}',
            ),
            RuleMock(ObjectName="put_string_set", ReturnValue=""),
        ],
        Log={
            "actor": {"email": "nick@acme.io", "profileId": "11949494222400014922"},
            "id": {"applicationName": "login"},
            "ipAddress": "127.0.0.1",
            "events": [{"type": "login", "name": "login_success"}],
            "p_log_type": "GSuite.Reports",
            "p_parse_time": "2021-06-04 10:02:33.650807",
            "p_event_time": "2021-06-04 09:59:53.650807",
        },
    ),
    PantherRuleTest(
        Name="Zoom - Successful Login Event - No History",
        ExpectedResult=False,
        Mocks=[
            RuleMock(
                ObjectName="geoinfo_from_ip",
                ReturnValue='{ "region": "UnitTestRegion", "city": "UnitTestCity1", "country": "UnitTestCountry" }',
            ),
            RuleMock(ObjectName="get_string_set", ReturnValue=""),
            RuleMock(ObjectName="put_string_set", ReturnValue=""),
        ],
        Log={
            "email": "homer.simpson@example.io",
            "time": "2021-10-22 10:39:04Z",
            "type": "Sign in",
            "ip_address": "1.1.1.1",
            "client_type": "Browser",
            "p_log_type": "Zoom.Activity",
            "p_parse_time": "2021-06-04 10:02:33.650807",
            "p_event_time": "2021-06-04 09:59:53.650807",
        },
    ),
    PantherRuleTest(
        Name="Zoom - Successful Login Event",
        ExpectedResult=True,
        Mocks=[
            RuleMock(
                ObjectName="geoinfo_from_ip",
                ReturnValue='{ "region": "UnitTestRegion", "city": "UnitTestCity1", "country": "UnitTestCountry" }',
            ),
            RuleMock(
                ObjectName="get_string_set",
                ReturnValue='{"UnitTestRegion:UnitTestCity": "2021-06-04 09:59:53.650801"}',
            ),
            RuleMock(ObjectName="put_string_set", ReturnValue=""),
        ],
        Log={
            "email": "homer.simpson@example.io",
            "time": "2021-10-22 10:39:04Z",
            "type": "Sign in",
            "ip_address": "1.1.1.1",
            "client_type": "Browser",
            "p_log_type": "Zoom.Activity",
            "p_parse_time": "2021-06-04 10:02:33.650807",
            "p_event_time": "2021-06-04 09:59:53.650807",
        },
    ),
    PantherRuleTest(
        Name="1Password - Regular Login",
        ExpectedResult=True,
        Mocks=[
            RuleMock(
                ObjectName="geoinfo_from_ip",
                ReturnValue='{ "ip": "111.111.111.111", "region": "UnitTestRegion", "city": "UnitTestCityNew", "country": "UnitTestCountry", "hostname": "somedomain.com", "org": "Some Org" }',
            ),
            RuleMock(
                ObjectName="get_string_set",
                ReturnValue='{ "UnitTestRegion:UnitTestCity1": "2021-06-04 09:59:53.650801", "UnitTestRegion:UnitTestCity2": "2021-06-04 09:59:53.650802", "UnitTestRegion:UnitTestCity3": "2021-06-04 09:59:53.650803", "UnitTestRegion:UnitTestCity4": "2021-06-04 09:59:53.650804", "UnitTestRegion:UnitTestCity5": "2021-06-04 09:59:53.650805" }',
            ),
            RuleMock(ObjectName="put_string_set", ReturnValue=""),
        ],
        Log={
            "uuid": "1234",
            "session_uuid": "5678",
            "timestamp": "2021-12-03 19:52:52",
            "category": "success",
            "type": "credentials_ok",
            "country": "US",
            "target_user": {
                "email": "homer@springfield.gov",
                "name": "Homer Simpson",
                "uuid": "1234",
            },
            "client": {
                "app_name": "1Password Browser Extension",
                "app_version": "20184",
                "ip_address": "1.1.1.1",
                "os_name": "Solaris",
                "os_version": "10",
                "platform_name": "Chrome",
                "platform_version": "96.0.4664.55",
            },
            "p_log_type": "OnePassword.SignInAttempt",
            "p_parse_time": "2021-06-04 10:02:33.650807",
            "p_event_time": "2021-06-04 09:59:53.650807",
        },
    ),
    PantherRuleTest(
        Name="1Password - Failed Login",
        ExpectedResult=False,
        Mocks=[
            RuleMock(
                ObjectName="geoinfo_from_ip",
                ReturnValue='{ "ip": "111.111.111.111", "region": "UnitTestRegion", "city": "UnitTestCityNew", "country": "UnitTestCountry", "hostname": "somedomain.com", "org": "Some Org" }',
            )
        ],
        Log={
            "uuid": "1234",
            "session_uuid": "5678",
            "timestamp": "2021-12-03 19:52:52",
            "category": "credentials_failed",
            "type": "password_secret_bad",
            "country": "US",
            "target_user": {
                "email": "homer@springfield.gov",
                "name": "Homer Simpson",
                "uuid": "1234",
            },
            "client": {
                "app_name": "1Password Browser Extension",
                "app_version": "20184",
                "ip_address": "111.111.111.111",
                "os_name": "Solaris",
                "os_version": "10",
                "platform_name": "Chrome",
                "platform_version": "96.0.4664.55",
            },
            "p_log_type": "OnePassword.SignInAttempt",
            "p_parse_time": "2021-06-04 10:02:33.650807",
            "p_event_time": "2021-06-04 09:59:53.650807",
        },
    ),
]


class StandardUnusualLogin(PantherRule):
    RuleID = "Standard.UnusualLogin-prototype"
    DisplayName = "--DEPRECATED-- Unusual Login"
    Enabled = False
    LogTypes = [
        "Asana.Audit",
        "Atlassian.Audit",
        "AWS.CloudTrail",
        "GSuite.Reports",
        "Okta.SystemLog",
        "OneLogin.Events",
        "Zendesk.Audit",
        "Zoom.Activity",
        "OnePassword.SignInAttempt",
    ]
    Tags = ["DataModel", "Identity & Access Management", "Initial Access:Valid Accounts"]
    Reports = {"MITRE ATT&CK": ["TA0001:T1078"]}
    Severity = Severity.Medium
    Description = "A user logged in from a new geolocation."
    Runbook = "Reach out to the user to ensure the login was legitimate.  Be sure to use a means outside the one the unusual login originated from, if one is available. CC an individual that works with the user for visibility, usually the user’s manager if they’re available. The second user is not expected to respond, unless they find the response unusual or the location unexpected.\nTo reduce noise, geolocation history length can be configured in the rule body to increase the number of allowed locations per user.\n"
    Reference = "https://d3fend.mitre.org/technique/d3f:UserGeolocationLogonPatternAnalysis/"
    SummaryAttributes = ["p_any_ip_addresses"]
    Tests = standard_unusual_login_tests
    # This rule is disabled by default because it makes API calls to a third party geolocation
    # service. At high rates of log processing, the third party service may throttle requests
    # unless you buy a subscription to it, which may cause this rule to no longer work.
    # number of unique geolocation city:region combinations retained in the
    # panther-kv-table in Dynamo to suppress alerts
    GEO_HISTORY_LENGTH = 5
    GEO_INFO = {}
    GEO_HISTORY = {}

    def rule(self, event):
        # pylint: disable=too-complex
        # pylint: disable=too-many-branches
        # unique key for global dictionary
        log = event.get("p_row_id")
        # GEO_INFO is mocked as a string in unit tests and redeclared as a dict
        # Pre-filter to save compute time where possible.
        if event.udm("event_type") != event_type.SUCCESSFUL_LOGIN:
            return False
        # we use udm 'actor_user' field as a ddb and 'source_ip' in the api call
        if not event.udm("actor_user") or not event.udm("source_ip"):
            return False
        # Lookup geo-ip data via API call
        # Mocked during unit testing
        self.GEO_INFO[log] = geoinfo_from_ip(event.udm("source_ip"))
        # As of Panther 1.19, mocking returns all mocked objects in a string
        # GEO_INFO must be converted back to a dict to mimic the API call
        if isinstance(self.GEO_INFO[log], str):
            self.GEO_INFO[log] = json.loads(self.GEO_INFO[log])
        # Look up history of unique geolocations
        event_key = self.get_key(event)
        # Mocked during unit testing
        previous_geo_logins = get_string_set(event_key)
        # As of Panther 1.19, mocking returns all mocked objects in a string
        # previous_geo_logins must be converted back to a set to mimic the API call
        if isinstance(previous_geo_logins, str):
            logging.debug("previous_geo_logins is a mocked string:")
            logging.debug(previous_geo_logins)
            if previous_geo_logins:
                previous_geo_logins = set([previous_geo_logins])
            else:
                previous_geo_logins = set()
            logging.debug("new type of previous_geo_logins should be 'set':")
            logging.debug(type(previous_geo_logins))
        new_login_geo = f"{self.GEO_INFO[log].get('region', '<UNKNOWN_REGION>')}:{self.GEO_INFO[log].get('city', '<UNKNOWN_CITY>')}"
        new_login_timestamp = event.get("p_event_time", "")
        # convert set of single string to dictionary
        if previous_geo_logins:
            previous_geo_logins = json.loads(previous_geo_logins.pop())
        else:
            previous_geo_logins = {}
        logging.debug("new type of previous_geo_logins should be 'dict':")
        logging.debug(type(previous_geo_logins))
        # don't alert if the geo is already in the history
        if previous_geo_logins.get(new_login_geo):
            # update timestamp of the existing geo in the history
            previous_geo_logins[new_login_geo] = new_login_timestamp
            # write the dictionary of geolocs:timestamps back to Dynamo
            # Mocked during unit testing
            put_string_set(event_key, [json.dumps(previous_geo_logins)])
            return False
        # fire an alert when there are more unique geolocs:timestamps in the login history
        # add a new geo to the dictionary
        updated_geo_logins = previous_geo_logins
        updated_geo_logins[new_login_geo] = new_login_timestamp
        # remove the oldest geo from the history if the updated dict exceeds the
        # specified history length
        if len(updated_geo_logins) > self.GEO_HISTORY_LENGTH:
            oldest = updated_geo_logins[new_login_geo]
            for geo, time in updated_geo_logins.items():
                if time < oldest:
                    oldest = time
                    oldest_login = geo
            logging.debug("updated_geo_logins before removing oldest entry:")
            logging.debug(updated_geo_logins)
            updated_geo_logins.pop(oldest_login)
            logging.debug("updated_geo_logins after removing oldest entry:")
            logging.debug(updated_geo_logins)
        # Mocked during unit testing
        put_string_set(event_key, [json.dumps(updated_geo_logins)])
        self.GEO_HISTORY[log] = updated_geo_logins
        logging.debug("GEO_HISTORY in main rule:\n%s", json.dumps(self.GEO_HISTORY[log]))
        # Don't alert on first seen logins
        if len(updated_geo_logins) <= 1:
            return False
        return True

    def get_key(self, event) -> str:
        # Use the name to deconflict with other rules that may also use actor_user
        return __name__ + ":" + str(event.udm("actor_user"))

    def title(self, event):
        log = event.get("p_row_id")
        return f"{event.get('p_log_type')}: New access location for user [{event.udm('actor_user')}] from {self.GEO_INFO[log].get('city')}, {self.GEO_INFO[log].get('region')} in {self.GEO_INFO[log].get('country')} (not in last [{self.GEO_HISTORY_LENGTH}] login locations)"

    def alert_context(self, event):
        log = event.get("p_row_id")
        context = {}
        context["ip"] = event.udm("source_ip")
        context["reverse_lookup"] = self.GEO_INFO[log].get("hostname", "No reverse lookup hostname")
        context["ip_org"] = self.GEO_INFO[log].get("org", "No organization listed")
        if self.GEO_HISTORY[log]:
            context["geoHistory"] = f"{json.dumps(self.GEO_HISTORY[log])}"
        context = add_parse_delay(event, context)
        return context
