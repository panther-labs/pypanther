from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class SalesforceAdminLoginAsUser(Rule):
    default_description = "Salesforce detection that alerts when an admin logs in as another user. "
    display_name = "Salesforce Admin Login As User"
    default_runbook = "Please do an indicator search on USER_ID to find which user was assumed. "
    default_reference = "https://help.salesforce.com/s/articleView?id=sf.logging_in_as_another_user.htm&type=5"
    default_severity = Severity.INFO
    log_types = [LogType.SALESFORCE_LOGIN_AS]
    id = "Salesforce.Admin.Login.As.User-prototype"

    def rule(self, event):
        return event.get("EVENT_TYPE", "<NO_EVENT_TYPE_FOUND>") == "LoginAs"

    def title(self, event):
        admin = event.get("DELEGATED_USER_NAME", "<NO_ADMIN_FOUND>")
        user_id = event.get("USER_ID", "<NO_USER_ID_FOUND>")
        return f"Salesforce admin [{admin}] logged in as a regular user with the user id [{user_id}]."

    tests = [
        RuleTest(
            name="Normal Login Event",
            expected_result=False,
            log={
                "API_TYPE": "",
                "API_VERSION": "9998.0",
                "AUTHENTICATION_METHOD_REFERENCE": "",
                "BROWSER_TYPE": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/IP_ADDRESS_REMOVED Safari/537.36",
                "CIPHER_SUITE": "ECDHE-RSA-AES256-GCM-SHA384",
                "CLIENT_IP": "13.13.13.13",
                "CPU_TIME": 17,
                "DB_TOTAL_TIME": 19103758.0,
                "EVENT_TYPE": "Login",
                "LOGIN_KEY": "HMvXV5bu8xcZOqQl",
                "LOGIN_STATUS": "LOGIN_NO_ERROR",
                "ORGANIZATION_ID": "00D5f000005uVo7",
                "REQUEST_ID": "4pkDPOtDbNNyUOG-mNMVJ-",
                "REQUEST_STATUS": "",
                "RUN_TIME": 42,
                "SESSION_KEY": "",
                "SOURCE_IP": "12.12.12.12",
                "TIMESTAMP": "2023-05-04 21:36:47.569",
                "TIMESTAMP_DERIVED": "2023-05-04 21:36:47.569",
                "TLS_PROTOCOL": "TLSv1.2",
                "URI": "/index.jsp",
                "URI_ID_DERIVED": "",
                "USER_ID": "0055f00000CyENt",
                "USER_ID_DERIVED": "0055f00000CyENtAAN",
                "USER_NAME": "user@yourcompany.io",
                "USER_TYPE": "Standard",
                "p_any_actor_ids": ["0055f00000CyENt"],
                "p_any_emails": ["user@yourcompany.io"],
                "p_any_ip_addresses": ["12.12.12.12"],
                "p_any_trace_ids": ["4pkDPOtDbNNyUOG-mNMVJ-"],
                "p_any_usernames": ["user@yourcompany.io"],
                "p_event_time": "2023-05-04 21:36:47.569",
                "p_log_type": "Salesforce.Login",
                "p_parse_time": "2023-05-05 13:18:06.918",
                "p_row_id": "be9d5602aec3c1c0938a94fd1797cd0c",
                "p_schema_version": 0,
                "p_source_id": "c473d18f-927d-461f-9b1d-8e1f5ffa1b06",
                "p_source_label": "Salesforce - Prod",
                "p_timeline": "2023-05-04 21:36:47.569",
            },
        ),
        RuleTest(
            name="Admin Assumes User",
            expected_result=True,
            log={
                "CLIENT_IP": "12.12.12.12",
                "CPU_TIME": 19,
                "DELEGATED_USER_ID": "0054x000001L78a",
                "DELEGATED_USER_ID_DERIVED": "0054x000001L78aAAC",
                "DELEGATED_USER_NAME": "admin.user@yourcompany.io",
                "EVENT_TYPE": "LoginAs",
                "LOGIN_KEY": "n5sqLw+tah0tY/q9",
                "ORGANIZATION_ID": "000elibsdfkjsd",
                "REQUEST_ID": "4dmdpWcNWWjoaQWObxO2k-",
                "RUN_TIME": 1088,
                "SESSION_KEY": "f6wkL1crc62p7/Vj",
                "TIMESTAMP": "2021-08-19 09:05:03.392",
                "TIMESTAMP_DERIVED": "2021-08-19 09:05:03.392",
                "URI": "/secur/logout.jsp",
                "URI_ID_DERIVED": "",
                "USER_ID": "fdokawnjf",
                "USER_ID_DERIVED": "fdokawnjf",
                "p_any_ip_addresses": ["12.12.12.12"],
                "p_any_trace_ids": ["4dmdpWcNWWjoaQWObxO2k-"],
                "p_any_usernames": ["admin.user@yourcompany.io"],
                "p_event_time": "2021-08-19 09:05:03.392",
                "p_log_type": "Salesforce.LoginAs",
                "p_parse_time": "2021-08-19 11:11:32.69",
                "p_row_id": "1ac2cc960bb0ddf7dbeaeadb0ba701",
                "p_source_id": "2e4c927c-7461-4810-86fe-45f6d5c5fe5b",
                "p_source_label": "release-1-21",
            },
        ),
    ]
