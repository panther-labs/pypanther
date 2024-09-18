import unittest
from datetime import datetime, timedelta

import pytest

from pypanther import Severity
from pypanther.scheduled_rule import PantherFlowQuery, Period, Query, Schedule, ScheduledRule, SQLQuery


class TestScheduledRule(unittest.TestCase):
    def test_period_initialization(self):
        period = Period.from_minutes(30)
        self.assertEqual(period.total_minutes(), 30)
        self.assertEqual(str(period), "30m")

    def test_period_invalid_initialization(self):
        with self.assertRaises(ValueError):
            Period(timedelta(minutes=4))
        with self.assertRaises(ValueError):
            Period(timedelta(days=31))

    def test_schedule_initialization_with_cron(self):
        schedule = Schedule(cron="0 0 * * *")
        self.assertIsNotNone(schedule.cron)
        self.assertIsNone(schedule.period)

    def test_schedule_initialization_with_period(self):
        period = Period.from_hours(1)
        schedule = Schedule(period=period)
        self.assertIsNone(schedule.cron)
        self.assertEqual(schedule.period, period)

    def test_schedule_invalid_initialization(self):
        with self.assertRaises(ValueError):
            Schedule()
        with self.assertRaises(ValueError):
            Schedule(cron="0 0 * * *", period=Period.from_hours(1))

    def test_schedule_get_next_run_time(self):
        schedule = Schedule(cron="0 0 * * *")
        next_run_time = schedule.get_next_run_time()
        self.assertIsInstance(next_run_time, datetime)

    def test_schedule_get_prev_run_time(self):
        schedule = Schedule(cron="0 0 * * *")
        prev_run_time = schedule.get_prev_run_time()
        self.assertIsInstance(prev_run_time, datetime)

    def test_ocsf_brute_force_connections_query(self):
        rule = OCSFBruteForceConnections()
        query = rule.query()
        self.assertIsInstance(query, PantherFlowQuery)
        self.assertIn("ocsf_networkactivity", query.expression)

    def test_snowflake_brute_force_by_username_query(self):
        rule = SnowflakeBruteForceByUsername()
        query = rule.query
        self.assertIsInstance(query, SQLQuery)
        self.assertIn("snowflake.account_usage.login_history", query.expression)

    def test_snowflake_brute_force_by_username2_query(self):
        rule = SnowflakeBruteForceByUsername2()
        query = rule.query()
        self.assertIsInstance(query, SQLQuery)
        self.assertIn("snowflake.account_usage.login_history", query.expression)

    def test_snowflake_data_exfil_query(self):
        rule = SnowflakeDataExfil()
        query = rule.query()
        self.assertIsInstance(query, PantherFlowQuery)
        self.assertIn("panther_logs.public.signals", query.expression)

    def test_snowflake_file_downloaded_query(self):
        rule = SnowflakeFileDownloaded()
        query = rule.query()
        self.assertIsInstance(query, SQLQuery)
        self.assertIn("SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY", query.expression)

    def test_snowflake_copy_into_storage_query(self):
        rule = SnowflakeCopyIntoStorage()
        query = rule.query()
        self.assertIsInstance(query, str)
        self.assertIn("SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY", query)

    def test_snowflake_temp_stage_created_query(self):
        rule = SnowflakeTempStageCreated()
        query = rule.query
        self.assertIsInstance(query, str)
        self.assertIn("SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY", query)


class OCSFBruteForceConnections(ScheduledRule):
    id = "OCSF.VPC.BruteForceConnections"
    enabled = True
    default_severity = Severity.MEDIUM
    period = Period.from_minutes(30)
    refuse_count = 5

    def query(self):
        return PantherFlowQuery(
            expression=f"""
	            panther_logs.public.ocsf_networkactivity
	            | where p_event_time > time.ago({self.period})
	            | where metadata.product.name == 'Amazon VPC'
	            | where connection_info.direction == 'Inbound'
	            | where activity_name == 'Refuse'
	            | where dst_endpoint.port between 1 .. 1024
	            | summarize Count=agg.count() by dst_endpoint.interface_uid
	            | extend AboveThresh = Count >= {self.refuse_count}
	            | where AboveThresh
			      """,
            schedule=Schedule(period=self.period),
        )

    @classmethod
    def validate_config(cls):
        assert len(cls.refuse_count) is not None, "refuse_count must be set"

    def title(self, event):
        interface = event.get("dst_endpoint.interface_uid")
        return f"Endpoint [{interface}] has refused a high # of connections in the past {self.period}"


class SnowflakeBruteForceByUsername(ScheduledRule):
    id = "Snowflake.BruteForceByUsername"
    enabled = True
    default_severity = Severity.MEDIUM
    query = SQLQuery(
        expression="""
            SELECT
            user_name,
            reported_client_type,
            ARRAY_AGG(DISTINCT error_code) as error_codes,
            ARRAY_AGG(DISTINCT error_message) as error_messages,
            COUNT(event_id) AS counts
        FROM snowflake.account_usage.login_history
        WHERE
            DATEDIFF(HOUR, event_timestamp, CURRENT_TIMESTAMP) < 24
            AND event_type = 'LOGIN'
            AND error_code IS NOT NULL
        GROUP BY reported_client_type, user_name
        HAVING counts >=5;
        """,
        schedule=Schedule(period=Period.from_hours(24)),
        description="Detect brute force via failed logins to Snowflake",
    )

    def title(self, event):
        return f"User [{event.get('user_name')}] surpassed the failed logins threshold of 5"


class SnowflakeBruteForceByUsername2(ScheduledRule):
    id = "Snowflake.BruteForceByUsername"
    enabled = True
    default_severity = Severity.MEDIUM
    period = Period.from_days(1)

    failed_login_count = 12

    def query(self):
        return SQLQuery(
            description="Detect brute force failed logins to Snowflake",
            expression=f"""
				    SELECT
				        user_name,
				        reported_client_type,
				        ARRAY_AGG(DISTINCT error_code) as error_codes,
				        ARRAY_AGG(DISTINCT error_message) as error_messages,
				        COUNT(event_id) AS counts
				    FROM snowflake.account_usage.login_history
				    WHERE
				        DATEDIFF(HOUR, event_timestamp, CURRENT_TIMESTAMP) < {self.period}
				        AND event_type = 'LOGIN'
				        AND error_code IS NOT NULL
				    GROUP BY reported_client_type, user_name
				    HAVING counts >={self.failed_login_count};
				    """,
            schedule=Schedule(period=self.period),
        )

    def title(self, event):
        user = event.get("user_name")
        return f"Snowflake User [{user}] had more than [{self.failed_login_count}] failed logins"


# TODO(panther): Override only supports named class attributes, so arbitrary naming and interpolation into the query
# is not supported. This is a limitation of the current implementation and they must be called directly... For now..
# SnowflakeBruteForceByUsername2.override(
#     period=Period.from_hours(12),
#     failed_login_count=15,
# )
SnowflakeBruteForceByUsername2.period = Period.from_hours(12)
SnowflakeBruteForceByUsername2.failed_login_count = 15


class SnowflakeDataExfil(ScheduledRule):
    id = "Snowflake.DataExfil"
    enabled = True
    default_severity = Severity.HIGH
    period = Period.from_days(1)

    def query(self):
        return PantherFlowQuery(
            expression=f"""
                panther_logs.public.signals
                | where p_event_time > time.ago({self.period})
                | sequence
                    e1=(p_rule_id="{SnowflakeTempStageCreated.id}")
                    e2=(p_rule_id="{SnowflakeCopyIntoStorage.id}")
                    e3=(p_rule_id="{SnowflakeFileDownloaded.id}")
                | match on=("stage")
            """,
            schedule=Schedule(
                period=self.period,
                timeout_mins=15,
            ),
        )


class SnowflakeFileDownloaded(ScheduledRule):
    id = "Snowflake.FileDownloaded"
    description = "Query to detect Snowflake data being downloaded"
    enabled = True
    create_alert = False

    def query(self):
        return SQLQuery(
            expression="""
        SELECT 
            user_name,
            role_name,
            start_time AS p_event_time,
            query_type,
            execution_status,
            regexp_substr(query_text, 'GET\\s+(\\$\\$|\\\')?@([a-zA-Z0-9_\\.]+)', 1, 1, 'i', 2) as stage,
            regexp_substr(query_text, 'GET\\s+(\\$\\$|\\\')?@([a-zA-Z0-9_\\./]+)(\\$\\$|\\\')?\\s', 1, 1, 'i', 2) as path,
            query_text
        FROM 
            SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
        WHERE 
            query_type = 'GET_FILES' 
            AND path IS NOT NULL 
            AND p_occurs_since('1 day')
            AND execution_status = 'SUCCESS'
        LIMIT 100""",
            schedule=Schedule(
                cron="@daily",
                timeout_mins=5,
            ),
        )


class SnowflakeCopyIntoStorage(ScheduledRule):
    id = "Snowflake.CopyIntoStorage"
    description = "Query to detect Snowflake data being copied into storage"

    enabled = True
    create_alert = False

    schedule = Schedule(
        cron="@daily",
        timeout_mins=5,
    )

    def query(self):
        return """
        SELECT 
            user_name,
            role_name,
            start_time AS p_event_time,
            query_type,
            execution_status,
            regexp_substr(query_text, 'COPY\\s+INTO\\s+(\\$\\$|\\\')?@([a-zA-Z0-9_\\.]+)', 1, 1, 'i', 2) as stage,
            regexp_substr(query_text, 'COPY\\s+INTO\\s+(\\$\\$|\\\')?@([a-zA-Z0-9_\\./]+)(\\$\\$|\\\')?\\s+FROM', 1, 1, 'i', 2) as path,
            query_text
        FROM 
            SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
        WHERE 
            query_type = 'UNLOAD' 
            AND stage IS NOT NULL 
            AND p_occurs_since('1 day')
            AND execution_status = 'SUCCESS'
        LIMIT 100
        """


class SnowflakeTempStageCreated(ScheduledRule):
    id = "Snowflake.TempStageCreated"
    description = "Query to detect Snowflake temporary stages created"

    enabled = True
    create_alert = False

    schedule = Schedule(
        cron="@daily",
        timeout_mins=5,
    )

    query = """
    SELECT 
        user_name,
        role_name,
        start_time AS p_event_time,
        query_type,
        execution_status,
        regexp_substr(query_text, 'CREATE\\s+(OR\\s+REPLACE\\s+)?(TEMPORARY\\s+|TEMP\\s+)STAGE\\s+(IF\\s+NOT\\s+EXISTS\\s+)?([a-zA-Z0-9_\\.]+)', 1, 1, 'i', 4) as stage,
        query_text
    FROM 
        SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
    WHERE 
        query_type = 'CREATE' 
        AND stage IS NOT NULL 
        AND p_occurs_since('1 day') 
        AND execution_status = 'SUCCESS'
    LIMIT 100
    """


class SnowflakeExteralShare(ScheduledRule):
    id = "Snowflake.External.Shares"
    enabled = True
    query = SQLQuery(
        description="Query to detect Snowflake data transfers across cloud accounts",
        expression="""
            SELECT 
                *
            FROM 
                snowflake.account_usage.data_transfer_history
            WHERE
                DATEDIFF(HOUR, start_time, CURRENT_TIMESTAMP) < 24
                AND start_time IS NOT NULL
                AND source_cloud IS NOT NULL
                AND target_cloud IS NOT NULL
                AND bytes_transferred > 0
        """,
        schedule=Schedule(
            cron="@daily",
            timeout_mins=2,
        ),
    )

    def title(self, event):
        return (
            "A data export has been initiated from source cloud "
            f"[{event.get('source_cloud','<SOURCE_CLOUD_NOT_FOUND>')}] "
            f"in source region [{event.get('source_region','<SOURCE_REGION_NOT_FOUND>')}] "
            f"to target cloud [{event.get('target_cloud','<TARGET_CLOUD_NOT_FOUND>')}] "
            f"in target region [{event.get('target_region','<TARGET_REGION_NOT_FOUND>')}] "
            f"with transfer type [{event.get('transfer_type','<TRANSFER_TYPE_NOT_FOUND>')}] "
            f"for [{event.get('bytes_transferred','<BYTES_NOT_FOUND>')}] bytes."
        )
