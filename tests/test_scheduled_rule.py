import unittest
from datetime import datetime, timedelta

import pytest

from pypanther import Severity
from pypanther.scheduled_rule import PantherFlowQuery, Period, Schedule, ScheduledRule, SQLQuery


class OCSFBruteForceConnections(ScheduledRule):
    id = "OCSF.VPC.BruteForceConnections"
    enabled = True
    default_severity = Severity.MEDIUM
    query = PantherFlowQuery(
        expression="""
                panther_logs.public.ocsf_networkactivity
                | where p_event_time > time.ago({period})
                | where metadata.product.name == 'Amazon VPC'
                | where connection_info.direction == 'Inbound'
                | where activity_name == 'Refuse'
                | where dst_endpoint.port between 1 .. {max_dst_port}
                | summarize Count=agg.count() by dst_endpoint.interface_uid
                | extend AboveThresh = Count >= {refuse_count}
                | where AboveThresh
        """,
        params=PantherFlowQuery.Params(
            refuse_count=5,
            period=Period.from_minutes(30),
            max_dst_port=1024,
        ),
    )
    schedule = Schedule(period=Period.from_minutes(30))

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
        description="Detect brute force via failed logins to Snowflake",
    )
    schedule = Schedule(period=Period.from_hours(24))

    def title(self, event):
        return f"User [{event.get('user_name')}] surpassed the failed logins threshold of 5"


class SnowflakeBruteForceByUsernameParams(ScheduledRule):
    id = "Snowflake.BruteForceByUsername"
    enabled = True
    default_severity = Severity.MEDIUM

    query = SQLQuery(
        description="Detect brute force failed logins to Snowflake",
        expression="""
            SELECT
                user_name,
                reported_client_type,
                ARRAY_AGG(DISTINCT error_code) as error_codes,
                ARRAY_AGG(DISTINCT error_message) as error_messages,
                COUNT(event_id) AS counts
            FROM snowflake.account_usage.login_history
            WHERE
                DATEDIFF(HOUR, event_timestamp, CURRENT_TIMESTAMP) < {period}
                AND event_type = 'LOGIN'
                AND error_code IS NOT NULL
            GROUP BY reported_client_type, user_name
            HAVING counts >= {failed_login_count};
            """,
        params=SQLQuery.Params(failed_login_count=12, period=24),
    )
    schedule = Schedule(
        cron="@daily",
        timeout_mins=15,
    )

    def title(self, event):
        user = event.get("user_name")
        return f"Snowflake User [{user}] had more than [{self.failed_login_count}] failed logins"


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
    )
    schedule = Schedule(
        cron="@daily",
        timeout_mins=2,
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


class TestScheduledRule(unittest.TestCase):
    def test_period_initialization(self):
        period = Period.from_minutes(30)
        self.assertEqual(period.total_minutes(), 30)
        self.assertEqual(str(period), "30m")

    def test_period_invalid_initialization(self):
        with pytest.raises(ValueError, match="Period must be set between 5 mins and 30 days"):
            Period(timedelta(minutes=4))
        with pytest.raises(ValueError, match="Period must be set between 5 mins and 30 days"):
            Period(timedelta(days=31))

    def test_schedule_initialization_with_cron(self):
        schedule = Schedule(cron="0 0 * * *")
        self.assertIsNotNone(schedule.cron)
        self.assertIsNone(schedule.period)

    def test_schedule_initialization_with_daily_cron(self):
        schedule = Schedule(cron="@daily")
        self.assertIsNotNone(schedule.cron)
        self.assertIsNone(schedule.period)

    def test_schedule_invalid_cron_expression(self):
        with pytest.raises(ValueError, match="Invalid cron expression: invalid_cron"):
            Schedule(cron="invalid_cron")

    def test_schedule_initialization_with_period(self):
        period = Period.from_hours(1)
        schedule = Schedule(period=period)
        self.assertIsNone(schedule.cron)
        self.assertEqual(schedule.period, period)

    def test_schedule_invalid_initialization(self):
        with pytest.raises(ValueError, match="Either cron or period must be provided"):
            Schedule()
        with pytest.raises(ValueError, match="Cannot provide both cron and period"):
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
        self.assertIsInstance(rule.query, PantherFlowQuery)
        self.assertIn("ocsf_networkactivity", rule.query.expression)

    def test_override_query_params(self):
        rule = OCSFBruteForceConnections()
        self.assertEqual(rule.query.params.refuse_count, 5)

        # Override the query params
        rule.query.params.refuse_count = 10
        self.assertEqual(rule.query.params.refuse_count, 10)

        # Ensure the new value is reflected in the formatted expression
        formatted_expression = rule.query.format_expression()
        self.assertIn("Count >= 10", formatted_expression)

    def test_override_schedule(self):
        rule = OCSFBruteForceConnections()
        self.assertEqual(rule.schedule.period.total_minutes(), 30)

        # Override the schedule period
        rule.schedule.period = Period.from_minutes(60)
        self.assertEqual(rule.schedule.period.total_minutes(), 60)

        # Ensure the new value is reflected in the schedule
        self.assertEqual(rule.schedule.period.to_string(), "1h")

        # TODO(panther): Add support for abnormal intervals (this test fails today)
        # # Override the schedule period
        # rule.schedule.period = Period.from_minutes(90)
        # self.assertEqual(rule.schedule.period.total_minutes(), 90)

        # # Ensure the new value is reflected in the schedule
        # self.assertEqual(rule.schedule.period.to_string(), "90m")

    def test_snowflake_brute_force_by_username_query(self):
        rule = SnowflakeBruteForceByUsername()
        query = rule.query
        self.assertIsInstance(query, SQLQuery)
        self.assertIn("snowflake.account_usage.login_history", query.expression)

    def test_snowflake_brute_force_by_username_params(self):
        rule = SnowflakeBruteForceByUsernameParams()
        assert hasattr(rule.query.params, "failed_login_count"), "Missing param [failed_login_count]"

        # Override the query params
        rule.query.params.period = 10
        rule.query.params.failed_login_count = 15

        self.assertEqual(rule.query.params.failed_login_count, 15)
        self.assertEqual(rule.query.params.period, 10)

        # Ensure the new value is reflected in the formatted expression
        formatted_expression = rule.query.format_expression()
        self.assertIn("DATEDIFF(HOUR, event_timestamp, CURRENT_TIMESTAMP) < 10", formatted_expression)
        self.assertIn("HAVING counts >= 15", formatted_expression)
