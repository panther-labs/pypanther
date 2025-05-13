from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class SnowflakeStreamLoginWithoutMFA(Rule):
    id = "Snowflake.Stream.LoginWithoutMFA-prototype"
    display_name = "Snowflake Login Without MFA"
    enabled = False
    log_types = [LogType.SNOWFLAKE_LOGIN_HISTORY]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0005:T1556"]}
    default_description = "Detect Snowflake logins without multifactor authentication"
    dedup_period_minutes = 1440
    tags = ["Snowflake", "[MITRE] Defense Evasion", "[MITRE] Modify Authentication Process"]
    MFA_EXCEPTIONS = {"PANTHER_READONLY", "PANTHER_ADMIN", "PANTHERACCOUNTADMIN"}

    def rule(self, event):
        return all(
            (
                event.get("EVENT_TYPE") == "LOGIN",
                event.get("IS_SUCCESS") == "YES",
                event.get("FIRST_AUTHENTICATION_FACTOR") == "PASSWORD",
                not event.get("SECOND_AUTHENTICATION_FACTOR"),
                event.get("USER_NAME") not in self.MFA_EXCEPTIONS,
            ),
        )

    def title(self, event):
        source = event.get("p_source_label", "<UNKNOWN SOURCE>")
        user = event.get("USER_NAME", "<UNKNOWN USER>")
        return f"{source}: User {user} logged in without MFA"

    tests = [
        RuleTest(
            name="Login With MFA",
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
                "SECOND_AUTHENTICATION_FACTOR": "OTP",
                "USER_NAME": "ckent@dailyplanet.org",
            },
        ),
        RuleTest(
            name="Login Without MFA",
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
                "IS_SUCCESS": "YES",
                "RELATED_EVENT_ID": "0",
                "REPORTED_CLIENT_TYPE": "OTHER",
                "REPORTED_CLIENT_VERSION": "1.11.1",
                "USER_NAME": "luthor@lexcorp.com",
            },
        ),
    ]
