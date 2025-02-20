import re

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.snowflake import query_history_alert_context


@panther_managed
class SnowflakeStreamUserCreated(Rule):
    id = "Snowflake.Stream.UserCreated-prototype"
    display_name = "Snowflake User Created"
    enabled = False
    log_types = [LogType.SNOWFLAKE_QUERY_HISTORY]
    default_severity = Severity.INFO
    reports = {"MITRE ATT&CK": ["TA0003:T1136"]}
    default_description = "Detect new users created in Snowflake."
    tags = ["Snowflake", "[MITRE] Persistence", "[MITRE] Create Account"]
    CREATE_USER_EXPR = re.compile("create user (\\w+).*", flags=re.I)
    CREATE_USER = ""

    def rule(self, event):
        self.CREATE_USER = self.CREATE_USER_EXPR.match(event.get("QUERY_TEXT", ""))
        return all(
            (
                event.get("EXECUTION_STATUS") == "SUCCESS",
                event.get("QUERY_TYPE") == "CREATE_USER",
                self.CREATE_USER is not None,
            ),
        )

    def title(self, event):
        new_user = self.CREATE_USER.group(1)
        actor = event.get("user_name", "<UNKNOWN ACTOR>")
        source = event.get("p_source_label", "<UNKNOWN SOURCE>")
        return f"{source}: Snowflake user {new_user} created by {actor}"

    def alert_context(self, event):
        return query_history_alert_context(event)

    tests = [
        RuleTest(
            name="User Created",
            expected_result=True,
            log={
                "p_event_time": "2024-10-09 19:43:05.007000000",
                "p_log_type": "Snowflake.QueryHistory",
                "BYTES_DELETED": 0,
                "EXECUTION_STATUS": "SUCCESS",
                "QUERY_TEXT": "CREATE USER MERCY\nPASSWORD = '☺☺☺☺☺'\nDEFAULT_ROLE = PUBLIC;",
                "QUERY_TYPE": "CREATE_USER",
                "ROLE_NAME": "ACCOUNTADMIN",
                "USER_NAME": "LEX_LUTHOR",
                "WAREHOUSE_NAME": "ADMIN_WH",
            },
        ),
    ]
