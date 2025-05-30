import re

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class SnowflakeStreamTableCopiedIntoStage(Rule):
    id = "Snowflake.Stream.TableCopiedIntoStage-prototype"
    display_name = "Snowflake Table Copied Into Stage"
    log_types = [LogType.SNOWFLAKE_QUERY_HISTORY]
    default_severity = Severity.INFO
    create_alert = False
    reports = {"MITRE ATT&CK": ["TA0010:T1041"]}
    default_description = "A table was copied into a stage."
    default_reference = (
        "https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion/"
    )
    tags = ["Snowflake", "[MITRE] Exfiltration", "[MITRE] Exfiltration Over C2 Channel"]
    STAGE_EXPR = re.compile("COPY\\s+INTO\\s+(?:\\$\\$|')?@([\\w\\.]+)", flags=re.I)
    PATH_EXPR = re.compile("COPY\\s+INTO\\s+(?:\\$\\$|')?@([\\w\\./]+)(?:\\$\\$|')?\\s+FROM", flags=re.I)
    STAGE = ""

    def rule(self, event):
        self.STAGE = self.STAGE_EXPR.match(event.get("QUERY_TEXT", ""))
        return all(
            (event.get("QUERY_TYPE") == "UNLOAD", self.STAGE is not None, event.get("EXECUTION_STATUS") == "SUCCESS"),
        )

    def alert_context(self, event):
        path = self.PATH_EXPR.match(event.get("QUERY_TEXT", ""))
        return {"actor": event.get("USER_NAME"), "path": path.group(1), "stage": self.STAGE.group(1).lower()}

    tests = [
        RuleTest(
            name="Copy from Table into Stage",
            expected_result=True,
            log={
                "EXECUTION_STATUS": "SUCCESS",
                "QUERY_TEXT": "COPY INTO '@PANTHER_LOGS.PUBLIC.data_exfil/DATA.csv' FROM (SELECT * FROM PANTHER_LOGS.PUBLIC.amazon_eks_audit LIMIT 100) FILE_FORMAT = ( TYPE='CSV' COMPRESSION=GZIP FIELD_DELIMITER=',' ESCAPE=NONE ESCAPE_UNENCLOSED_FIELD=NONE date_format='AUTO' time_format='AUTO' timestamp_format='AUTO' binary_format='UTF-8' null_if='' EMPTY_FIELD_AS_NULL = FALSE ) overwrite=TRUE single=FALSE max_file_size=5368709120 header=TRUE",
                "QUERY_TYPE": "UNLOAD",
                "USER_NAME": "LEX_LUTHOR",
            },
        ),
        RuleTest(
            name="Copy from Stage into Table",
            expected_result=False,
            log={
                "EXECUTION_STATUS": "SUCCESS",
                "QUERY_TEXT": "COPY INTO mytable\nFROM @mystage/result/data_ FILE_FORMAT = (FORMAT_NAME='CSV' COMPRESSION='GZIP');",
                "QUERY_TYPE": "UNLOAD",
                "USER_NAME": "LEX_LUTHOR",
            },
        ),
    ]
