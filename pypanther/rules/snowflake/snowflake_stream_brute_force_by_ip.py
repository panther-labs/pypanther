from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class SnowflakeStreamBruteForceByIp(Rule):
    id = "Snowflake.Stream.BruteForceByIp-prototype"
    display_name = "Snowflake Brute Force Attacks by IP"
    log_types = [LogType.SNOWFLAKE_LOGIN_HISTORY]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0006:T1110"]}
    default_description = "Detect brute force attacks by monitorign failed logins from the same IP address"
    threshold = 5
    tags = ["Snowflake", "[MITRE] Credential Access", "[MITRE] Brute Force"]

    def rule(self, event):
        # Return true for any login attempt; Let Panther's dedup and threshold handle the brute force
        #   detection.
        return event.get("EVENT_TYPE") == "LOGIN" and event.get("IS_SUCCESS") == "NO"

    def title(self, event):
        return (
            f"Login attempts from IP {event.get('CLIENT_IP', '<UNKNOWN IP>')} have exceeded the failed logins threshold"
        )

    def dedup(self, event):
        return event.get("CLIENT_IP", "<UNKNOWN IP>") + event.get("REPORTED_CLIENT_TYPE", "<UNKNOWN CLIENT TYPE>")

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
    ]
