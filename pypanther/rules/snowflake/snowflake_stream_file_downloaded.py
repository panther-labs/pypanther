import re

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.snowflake import query_history_alert_context


@panther_managed
class SnowflakeStreamFileDownloaded(Rule):
    id = "Snowflake.Stream.FileDownloaded-prototype"
    display_name = "Snowflake File Downloaded"
    log_types = [LogType.SNOWFLAKE_QUERY_HISTORY]
    default_severity = Severity.INFO
    create_alert = False
    reports = {"MITRE ATT&CK": ["TA0010:T1041"]}
    default_description = "A file was downloaded from a stage."
    default_reference = (
        "https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion/"
    )
    tags = ["Snowflake", "[MITRE] Exfiltration", "[MITRE] Exfiltration Over C2 Channel"]
    PATH_EXPR = re.compile("GET\\s+(?:\\$\\$|')?@([a-zA-Z0-9_\\./]+)(?:\\$\\$|')?\\s", flags=re.I)
    STAGE_EXPR = re.compile("GET\\s+(?:\\$\\$|')?@([a-zA-Z0-9_\\.]+)", flags=re.I)
    PATH = ""
    STAGE = ""

    def rule(self, event):
        # Check these conditions first to avoid running an expensive regex on every log
        if not all(
            (
                event.get("QUERY_TYPE") == "GET_FILES",
                event.get("EXECUTION_STATUS") == "SUCCESS",
                event.get("QUERY_TEXT") != "GET '@~/worksheet_data/metadata' 'file:///'",
            ),
        ):
            # Avoid alerting for fetching worksheets:
            return False
        self.PATH = self.PATH_EXPR.search(event.get("QUERY_TEXT", ""))
        return self.PATH is not None

    def alert_context(self, event):
        self.STAGE = self.STAGE_EXPR.match(event.get("QUERY_TEXT", ""))
        return query_history_alert_context(event) | {
            "path": self.PATH.group(1),
            "stage": None if not self.STAGE else self.STAGE.group(1).lower(),
        }

    tests = [
        RuleTest(
            name="Worksheet File Downloaded",
            expected_result=False,
            log={
                "p_event_time": "2024-10-09 19:38:06.158000000",
                "p_log_type": "Snowflake.QueryHistory",
                "p_source_label": "SF-Ben",
                "EXECUTION_STATUS": "SUCCESS",
                "QUERY_TEXT": "GET '@~/worksheet_data/metadata' 'file:///'",
                "QUERY_TYPE": "GET_FILES",
                "ROLE_NAME": "PUBLIC",
                "USER_NAME": "CLARK_KENT",
            },
        ),
        RuleTest(
            name="Other File Downloaded",
            expected_result=True,
            log={
                "p_event_time": "2024-10-09 19:38:06.158000000",
                "p_log_type": "Snowflake.QueryHistory",
                "p_source_label": "SF-Ben",
                "EXECUTION_STATUS": "SUCCESS",
                "QUERY_TEXT": "GET @PANTHER_LOGS.PUBLIC.data_exfil/DATA.csv 'file:///Users/lex.luthor/Documents'",
                "QUERY_TYPE": "GET_FILES",
                "ROLE_NAME": "PUBLIC",
                "USER_NAME": "LEX_LUTHOR",
            },
        ),
    ]
