from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class SnowflakeStreamBruteForceByUsername(Rule):
    id = "Snowflake.Stream.BruteForceByUsername-prototype"
    display_name = "Snowflake Brute Force Attacks by User"
    log_types = [LogType.SNOWFLAKE_LOGIN_HISTORY]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0006:T1110"]}
    default_description = "Detect brute force attacks by monitorign failed logins from the same IP address"
    threshold = 5
    tags = ["Snowflake", "[MITRE] Credential Access", "[MITRE] Brute Force"]

    def rule(self, event):
        # Return true for any login attempt; Let Panther's dedup and threshold handle the brute force
        #   detection.
        # ^^ OVERFLOW_FAILURE_EVENTS_ELIDED are placeholder logs -> no point in alerting
        return (
            event.get("EVENT_TYPE") == "LOGIN"
            and event.get("IS_SUCCESS") == "NO"
            and (event.get("ERROR_MESSAGE") != "OVERFLOW_FAILURE_EVENTS_ELIDED")
        )

    def title(self, event):
        return f"User {event.get('USER_NAME', '<UNKNOWN USER>')} has exceeded the failed logins threshold"

    def severity(self, event):
        # If the error appears to be caused by an automation issue, downgrade to INFO
        common_errors = {"JWT_TOKEN_INVALID_PUBLIC_KEY_FINGERPRINT_MISMATCH"}
        if event.get("ERROR_MESSAGE") in common_errors:
            return "INFO"
        return "DEFAULT"

    def dedup(self, event):
        return event.get("USER_NAME", "<UNKNOWN USER>") + event.get("REPORTED_CLIENT_TYPE", "<UNKNOWN CLIENT TYPE>")

    tests = [
        RuleTest(
            name="Successful Login",
            expected_result=False,
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
            expected_result=True,
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
        RuleTest(
            name="Unsuccessful Login due to Invalid JWT Fingerprint",
            expected_result=True,
            log={
                "p_event_time": "2024-10-08 14:38:46.061000000",
                "p_log_type": "Snowflake.LoginHistory",
                "p_source_label": "Snowflake Prod",
                "CLIENT_IP": "1.2.3.4",
                "ERROR_CODE": 394304,
                "ERROR_MESSAGE": "JWT_TOKEN_INVALID_PUBLIC_KEY_FINGERPRINT_MISMATCH",
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
        RuleTest(
            name="Overflow Failure",
            expected_result=False,
            log={
                "p_event_time": "2024-11-15 00:12:24.288000000",
                "p_log_type": "Snowflake.LoginHistory",
                "p_parse_time": "2024-11-15 02:46:25.862374468",
                "CLIENT_IP": "0.0.0.0",
                "ERROR_CODE": 390156,
                "ERROR_MESSAGE": "OVERFLOW_FAILURE_EVENTS_ELIDED",
                "EVENT_ID": "16592193114297018",
                "EVENT_TIMESTAMP": "2024-11-15 00:12:24.288000000",
                "EVENT_TYPE": "LOGIN",
                "IS_SUCCESS": "NO",
                "RELATED_EVENT_ID": "0",
                "REPORTED_CLIENT_TYPE": "OTHER",
                "REPORTED_CLIENT_VERSION": "0",
                "USER_NAME": "luthor@lexcorp.com",
            },
        ),
    ]
