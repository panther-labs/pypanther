import re

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.snowflake import query_history_alert_context


@panther_managed
class SnowflakeStreamUserEnabled(Rule):
    id = "Snowflake.Stream.UserEnabled-prototype"
    display_name = "Snowflake User Enabled"
    log_types = [LogType.SNOWFLAKE_QUERY_HISTORY]
    default_severity = Severity.INFO
    reports = {"MITRE ATT&CK": ["TA0003:T1136"]}
    default_description = "Detects users being re-enabled in your environment."
    tags = ["Snowflake", "[MITRE] Persistence", "[MITRE] Create Account"]
    USER_ENABLED_EXPR = re.compile("alter\\s+user\\s+(.+?)\\s+.*?set\\s+disabled\\s*=\\s*false", flags=re.I)
    USER_ENABLED = ""

    def rule(self, event):
        self.USER_ENABLED = self.USER_ENABLED_EXPR.match(event.get("QUERY_TEXT", ""))
        # Exit out early to avoid needless regex
        return all(
            (
                event.get("QUERY_TYPE") == "ALTER_USER",
                event.get("EXECUTION_STATUS") == "SUCCESS",
                self.USER_ENABLED is not None,
            ),
        )

    def title(self, event):
        enabled_user = self.USER_ENABLED.group(1)
        actor = event.get("USER_NAME", "<UNKNOWN ACTOR>")
        source = event.get("p_source_label", "<UNKNOWN SOURCE>")
        return f"{source}: Snowflake user {enabled_user} enabled by {actor}"

    def alert_context(self, event):
        return query_history_alert_context(event)

    tests = [
        RuleTest(
            name="User Enabled",
            expected_result=True,
            log={
                "p_event_time": "2024-10-09 21:03:25.750000000",
                "p_log_type": "Snowflake.QueryHistory",
                "p_row_id": "6283439ab35193e891ac9ea1227b",
                "p_source_label": "SF-Ben",
                "EXECUTION_STATUS": "SUCCESS",
                "QUERY_TEXT": "ALTER USER CLARK_KENT SET DISABLED=FALSE;",
                "QUERY_TYPE": "ALTER_USER",
                "ROLE_NAME": "ACCOUNTADMIN",
                "USER_NAME": "LEX_LUTHOR",
                "WAREHOUSE_NAME": "DATAOPS_WH",
            },
        ),
        RuleTest(
            name="User Disabled",
            expected_result=False,
            log={
                "p_event_time": "2024-10-09 21:03:25.750000000",
                "p_log_type": "Snowflake.QueryHistory",
                "p_row_id": "6283439ab35193e891ac9ea1227b",
                "p_source_label": "SF-Ben",
                "EXECUTION_STATUS": "SUCCESS",
                "QUERY_TEXT": "ALTER USER CLARK_KENT SET DISABLED=TRUE;",
                "QUERY_TYPE": "ALTER_USER",
                "ROLE_NAME": "ACCOUNTADMIN",
                "USER_NAME": "PERRY_WHITE",
                "WAREHOUSE_NAME": "DATAOPS_WH",
            },
        ),
    ]
