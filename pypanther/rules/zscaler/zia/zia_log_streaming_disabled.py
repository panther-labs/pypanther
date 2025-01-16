from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.zscaler import zia_alert_context, zia_success


@panther_managed
class ZIALogStreamingDisabled(Rule):
    id = "ZIA.Log.Streaming.Disabled-prototype"
    default_description = "This rule detects when ZIA log streaming was disabled."
    display_name = "ZIA Log Streaming Disabled"
    default_runbook = "Verify that this change was planned. If not, make sure to restore previous settings."
    default_reference = "https://help.zscaler.com/zia/about-nss-feeds"
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0005:T1562.008"]}
    log_types = [LogType.ZSCALER_ZIA_ADMIN_AUDIT_LOG]

    def rule(self, event):
        if not zia_success(event):
            return False
        action = event.deep_get("event", "action", default="ACTION_NOT_FOUND")
        category = event.deep_get("event", "category", default="CATEGORY_NOT_FOUND")
        if action == "DELETE" and category == "NSS":
            return True
        return False

    def title(self, event):
        cloud_connection_url = event.deep_get(
            "event",
            "preaction",
            "cloudNssSiemConfiguration",
            "connectionURL",
            default="<CLOUD_CONNECTION_URL_NOT_FOUND>",
        )
        return f"[Zscaler.ZIA]: Log streaming for location [{cloud_connection_url}] was deleted by admin with id [{event.deep_get('event', 'adminid', default='<ADMIN_ID_NOT_FOUND>')}]"

    def alert_context(self, event):
        return zia_alert_context(event)

    tests = [
        RuleTest(
            name="Log streaming disabled (NSS deleted)",
            expected_result=True,
            log={
                "event": {
                    "action": "DELETE",
                    "adminid": "admin@test.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "NSS",
                    "clientip": "1.2.3.4",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {},
                    "preaction": {
                        "cloudNss": True,
                        "cloudNssSiemConfiguration": {
                            "connectionHeaders": ["123:123"],
                            "connectionURL": "https://logs.company.net/http/a7adc684-f65c-42af-9519-0a0786656f20",
                            "lastSuccessFullTest": 0,
                            "maxBatchSize": 512,
                            "nssType": "NSS_FOR_WEB",
                            "oAuthAuthentication": False,
                            "siemType": "OTHER",
                            "testConnectivityCode": 0,
                        },
                        "customEscapedCharacter": ["ASCII_44", "ASCII_92", "ASCII_34"],
                        "duplicateLogs": 0,
                        "epsRateLimit": 0,
                        "feedOutputFormat": '\\{ "sourcetype" : "zscalernss-web", "event" : \\{"datetime":"%d{yy}-%02d{mth}-%02d{dd} %02d{hh}:%02d{mm}:%02d{ss}","reason":"%s{reason}","event_id":"%d{recordid}","protocol":"%s{proto}","action":"%s{action}","transactionsize":"%d{totalsize}","responsesize":"%d{respsize}","requestsize":"%d{reqsize}","urlcategory":"%s{urlcat}","serverip":"%s{sip}","requestmethod":"%s{reqmethod}","refererURL":"%s{ereferer}","useragent":"%s{eua}","product":"NSS","location":"%s{elocation}","ClientIP":"%s{cip}","status":"%s{respcode}","user":"%s{elogin}","url":"%s{eurl}","vendor":"Zscaler","hostname":"%s{ehost}","clientpublicIP":"%s{cintip}","threatcategory":"%s{malwarecat}","threatname":"%s{threatname}","filetype":"%s{filetype}","appname":"%s{appname}","app_status":"%s{app_status}","pagerisk":"%d{riskscore}","threatseverity":"%s{threatseverity}","department":"%s{edepartment}","urlsupercategory":"%s{urlsupercat}","appclass":"%s{appclass}","dlpengine":"%s{dlpeng}","urlclass":"%s{urlclass}","threatclass":"%s{malwareclass}","dlpdictionaries":"%s{dlpdict}","fileclass":"%s{fileclass}","bwthrottle":"%s{bwthrottle}","contenttype":"%s{contenttype}","unscannabletype":"%s{unscannabletype}","deviceowner":"%s{deviceowner}","devicehostname":"%s{devicehostname}","keyprotectiontype":"%s{keyprotectiontype}"\\}\\}\n',
                        "feedStatus": "ENABLED",
                        "id": 2898,
                        "jsonArrayToggle": True,
                        "name": "test-feed-2",
                        "nssFeedType": "JSON",
                        "nssFilter": {"securityFeedFilter": False},
                        "nssLogType": "WEBLOG",
                        "timeZone": "GMT",
                        "userObfuscation": "DISABLED",
                    },
                    "recordid": "371",
                    "resource": "test-feed-2",
                    "result": "SUCCESS",
                    "subcategory": "NSS_FEED",
                    "time": "2024-11-04 16:34:34.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
        RuleTest(
            name="NSS created",
            expected_result=False,
            log={
                "event": {
                    "action": "CREATE",
                    "adminid": "admin@test.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "NSS",
                    "clientip": "1.2.3.4",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {
                        "cloudNss": True,
                        "cloudNssSiemConfiguration": {
                            "clientSecret": "******",
                            "connectionHeaders": ["123:123"],
                            "connectionURL": "https://logs.company.net/http/a7adc684-f65c-42af-9519-0a0786656f20",
                            "lastSuccessFullTest": 0,
                            "maxBatchSize": 512,
                            "nssType": "NSS_FOR_WEB",
                            "oAuthAuthentication": False,
                            "siemType": "OTHER",
                            "testConnectivityCode": 0,
                        },
                        "customEscapedCharacter": ["ASCII_44", "ASCII_92", "ASCII_34"],
                        "duplicateLogs": 0,
                        "epsRateLimit": 0,
                        "feedOutputFormat": '\\{ "sourcetype" : "zscalernss-web", "event" : \\{"datetime":"%d{yy}-%02d{mth}-%02d{dd} %02d{hh}:%02d{mm}:%02d{ss}","reason":"%s{reason}","event_id":"%d{recordid}","protocol":"%s{proto}","action":"%s{action}","transactionsize":"%d{totalsize}","responsesize":"%d{respsize}","requestsize":"%d{reqsize}","urlcategory":"%s{urlcat}","serverip":"%s{sip}","requestmethod":"%s{reqmethod}","refererURL":"%s{ereferer}","useragent":"%s{eua}","product":"NSS","location":"%s{elocation}","ClientIP":"%s{cip}","status":"%s{respcode}","user":"%s{elogin}","url":"%s{eurl}","vendor":"Zscaler","hostname":"%s{ehost}","clientpublicIP":"%s{cintip}","threatcategory":"%s{malwarecat}","threatname":"%s{threatname}","filetype":"%s{filetype}","appname":"%s{appname}","app_status":"%s{app_status}","pagerisk":"%d{riskscore}","threatseverity":"%s{threatseverity}","department":"%s{edepartment}","urlsupercategory":"%s{urlsupercat}","appclass":"%s{appclass}","dlpengine":"%s{dlpeng}","urlclass":"%s{urlclass}","threatclass":"%s{malwareclass}","dlpdictionaries":"%s{dlpdict}","fileclass":"%s{fileclass}","bwthrottle":"%s{bwthrottle}","contenttype":"%s{contenttype}","unscannabletype":"%s{unscannabletype}","deviceowner":"%s{deviceowner}","devicehostname":"%s{devicehostname}","keyprotectiontype":"%s{keyprotectiontype}"\\}\\}\n',
                        "feedStatus": "ENABLED",
                        "id": 2898,
                        "jsonArrayToggle": True,
                        "name": "test-feed-2",
                        "nssFeedType": "JSON",
                        "nssFilter": {"securityFeedFilter": False},
                        "nssLogType": "WEBLOG",
                        "timeZone": "GMT",
                        "userObfuscation": "DISABLED",
                    },
                    "preaction": {
                        "cloudNss": True,
                        "cloudNssSiemConfiguration": {
                            "connectionHeaders": ["123:123"],
                            "connectionURL": "https://logs.company.net/http/a7adc684-f65c-42af-9519-0a0786621f20",
                            "maxBatchSize": 524288,
                            "nssType": "NSS_FOR_WEB",
                            "oAuthAuthentication": False,
                            "siemType": "OTHER",
                        },
                        "customEscapedCharacter": ["ASCII_44", "ASCII_92", "ASCII_34"],
                        "duplicateLogs": 0,
                        "epsRateLimit": 0,
                        "feedOutputFormat": '\\{ "sourcetype" : "zscalernss-web", "event" : \\{"datetime":"%d{yy}-%02d{mth}-%02d{dd} %02d{hh}:%02d{mm}:%02d{ss}","reason":"%s{reason}","event_id":"%d{recordid}","protocol":"%s{proto}","action":"%s{action}","transactionsize":"%d{totalsize}","responsesize":"%d{respsize}","requestsize":"%d{reqsize}","urlcategory":"%s{urlcat}","serverip":"%s{sip}","requestmethod":"%s{reqmethod}","refererURL":"%s{ereferer}","useragent":"%s{eua}","product":"NSS","location":"%s{elocation}","ClientIP":"%s{cip}","status":"%s{respcode}","user":"%s{elogin}","url":"%s{eurl}","vendor":"Zscaler","hostname":"%s{ehost}","clientpublicIP":"%s{cintip}","threatcategory":"%s{malwarecat}","threatname":"%s{threatname}","filetype":"%s{filetype}","appname":"%s{appname}","app_status":"%s{app_status}","pagerisk":"%d{riskscore}","threatseverity":"%s{threatseverity}","department":"%s{edepartment}","urlsupercategory":"%s{urlsupercat}","appclass":"%s{appclass}","dlpengine":"%s{dlpeng}","urlclass":"%s{urlclass}","threatclass":"%s{malwareclass}","dlpdictionaries":"%s{dlpdict}","fileclass":"%s{fileclass}","bwthrottle":"%s{bwthrottle}","contenttype":"%s{contenttype}","unscannabletype":"%s{unscannabletype}","deviceowner":"%s{deviceowner}","devicehostname":"%s{devicehostname}","keyprotectiontype":"%s{keyprotectiontype}"\\}\\}\n',
                        "feedStatus": "ENABLED",
                        "id": 0,
                        "jsonArrayToggle": True,
                        "name": "test-feed-2",
                        "nssFeedType": "JSON",
                        "nssFilter": {"securityFeedFilter": False},
                        "nssLogType": "WEBLOG",
                        "siemConfiguration": {},
                        "timeZone": "GMT",
                    },
                    "recordid": "370",
                    "resource": "test-feed-2",
                    "result": "SUCCESS",
                    "subcategory": "NSS_FEED",
                    "time": "2024-11-04 16:33:48.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
    ]
