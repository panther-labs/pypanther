import re

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.snowflake import query_history_alert_context


@panther_managed
class SnowflakeStreamTempStageCreated(Rule):
    id = "Snowflake.Stream.TempStageCreated-prototype"
    display_name = "Snowflake Temporary Stage Created"
    log_types = [LogType.SNOWFLAKE_QUERY_HISTORY]
    default_severity = Severity.INFO
    create_alert = False
    reports = {"MITRE ATT&CK": ["TA0010:T1041"]}
    default_description = "A temporary stage was created."
    default_reference = (
        "https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion/"
    )
    tags = ["Snowflake", "[MITRE] Exfiltration", "[MITRE] Exfiltration Over C2 Channel"]
    STAGE_EXPR = re.compile(
        "CREATE\\s+(?:OR\\s+REPLACE\\s+)?(?:TEMPORARY\\s+|TEMP\\s+)STAGE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?([a-zA-Z0-9_\\\\.]+)",
        flags=re.I,
    )
    STAGE = ""

    def rule(self, event):
        self.STAGE = self.STAGE_EXPR.match(event.get("QUERY_TEXT", ""))
        return all(
            (event.get("QUERY_TYPE") == "CREATE", event.get("EXECUTION_STATUS") == "SUCCESS", self.STAGE is not None),
        )

    def alert_context(self, event):
        return query_history_alert_context(event) | {"stage": self.STAGE.group(1)}

    tests = [
        RuleTest(
            name="Successful Temp Stage Created",
            expected_result=True,
            log={
                "p_event_time": "2024-10-09 21:06:03.631000000",
                "p_log_type": "Snowflake.QueryHistory",
                "p_source_id": "132d65cd-d6e4-4981-a209-a1d5902afd59",
                "p_source_label": "SF-Ben",
                "EXECUTION_STATUS": "SUCCESS",
                "QUERY_TEXT": "CREATE TEMP STAGE my_temp_stage;",
                "QUERY_TYPE": "CREATE",
                "USER_NAME": "LEX_LUTHOR",
                "WAREHOUSE_NAME": "ADMIN_WH",
            },
        ),
        RuleTest(
            name="Successful Temp Stage Created or Replaced",
            expected_result=True,
            log={
                "p_event_time": "2024-10-09 21:06:03.631000000",
                "p_log_type": "Snowflake.QueryHistory",
                "p_source_id": "132d65cd-d6e4-4981-a209-a1d5902afd59",
                "p_source_label": "SF-Ben",
                "EXECUTION_STATUS": "SUCCESS",
                "QUERY_TEXT": "CREATE OR REPLACE TEMP STAGE my_temp_stage;",
                "QUERY_TYPE": "CREATE",
                "USER_NAME": "LEX_LUTHOR",
                "WAREHOUSE_NAME": "ADMIN_WH",
            },
        ),
        RuleTest(
            name="Unsuccessful Temp Stage Created",
            expected_result=False,
            log={
                "p_event_time": "2024-10-09 21:06:03.631000000",
                "p_log_type": "Snowflake.QueryHistory",
                "p_source_id": "132d65cd-d6e4-4981-a209-a1d5902afd59",
                "p_source_label": "SF-Ben",
                "EXECUTION_STATUS": "FAIL",
                "QUERY_TEXT": "CREATE TEMP STAGE my_temp_stage;",
                "QUERY_TYPE": "CREATE",
                "USER_NAME": "LEX_LUTHOR",
                "WAREHOUSE_NAME": "ADMIN_WH",
            },
        ),
    ]
