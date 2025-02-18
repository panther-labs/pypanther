from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class SnowflakeStreamLoginSuccess(Rule):
    id = "Snowflake.Stream.LoginSuccess-prototype"
    display_name = "Snowflake Successful Login"
    log_types = [LogType.SNOWFLAKE_LOGIN_HISTORY]
    default_severity = Severity.INFO
    create_alert = False
    default_description = "Track successful login signals for correlation."
    tags = ["Snowflake"]

    def rule(self, event):
        return all((event.get("EVENT_TYPE") == "LOGIN", event.get("IS_SUCCESS") == "YES"))

    tests = [
        RuleTest(
            name="Successful Login",
            expected_result=True,
            log={
                "p_event_time": "2024-10-08 14:38:46.061000000",
                "p_log_type": "Snowflake.LoginHistory",
                "p_source_label": "Snowflake Prod",
                "CLIENT_IP": "1.1.1.1",
                "EVENT_ID": "393754014361778",
                "EVENT_TIMESTAMP": "2024-10-08 14:38:46.061000000",
                "EVENT_TYPE": "LOGIN",
                "FIRST_AUTHENTICATION_FACTOR": "PASSWORD",
                "IS_SUCCESS": "YES",
                "RELATED_EVENT_ID": "0",
                "REPORTED_CLIENT_TYPE": "OTHER",
                "REPORTED_CLIENT_VERSION": "1.11.1",
                "USER_NAME": "ckent@dailyplanet.org",
            },
        ),
        RuleTest(
            name="Unsuccessful Login",
            expected_result=False,
            log={
                "p_event_time": "2024-10-08 14:38:46.061000000",
                "p_log_type": "Snowflake.LoginHistory",
                "p_source_label": "Snowflake Prod",
                "CLIENT_IP": "1.2.3.4",
                "EVENT_ID": "393754014361778",
                "EVENT_TIMESTAMP": "2024-10-08 14:38:46.061000000",
                "EVENT_TYPE": "LOGIN",
                "FIRST_AUTHENTICATION_FACTOR": "PASSWORD",
                "IS_SUCCESS": "NO",
                "RELATED_EVENT_ID": "0",
                "REPORTED_CLIENT_TYPE": "OTHER",
                "REPORTED_CLIENT_VERSION": "1.11.1",
                "USER_NAME": "luthor@lexcorp.com",
            },
        ),
    ]
