from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.okta import okta_alert_context


@panther_managed
class OktaRefreshAccessTokenReuse(Rule):
    default_description = "When a client wants to renew an access token, it sends the refresh token with the access token request to the /token Okta endpoint.\nOkta validates the incoming refresh token, issues a new set of tokens and invalidates the refresh token that was passed with the initial request.\nThis detection alerts when a previously used refresh token is used again with the token request"
    default_reference = "https://developer.okta.com/docs/guides/refresh-tokens/main/#refresh-token-reuse-detection"
    display_name = "Okta App Refresh Access Token Reuse"
    default_runbook = "Determine if the clientip is anomalous. Revoke tokens if deemed suspicious."
    default_severity = Severity.MEDIUM
    log_types = [LogType.OKTA_SYSTEM_LOG]
    id = "Okta.Refresh.Access.Token.Reuse-prototype"

    def rule(self, event):
        return event.get("eventtype") in ("app.oauth2.as.token.detect_reuse", "app.oauth2.token.detect_reuse")

    def title(self, event):
        return f"Okta Access Token Reuse Attempted by [{event.get('client', {}).get('ipAddress')}] [{event.get('actor', {}).get('displayName', '<no-displayname-found>')}]"

    def alert_context(self, event):
        return okta_alert_context(event)

    tests = [
        RuleTest(
            name="Non-event",
            expected_result=False,
            log={
                "actor": {
                    "alternateId": "123456",
                    "displayName": "Okta User",
                    "id": "okta.1234.",
                    "type": "PublicClientApp",
                },
                "authenticationcontext": {"authenticationStep": 0, "externalSessionId": "123456789"},
                "client": {
                    "device": "Computer",
                    "geographicalContext": {
                        "city": "Queens",
                        "country": "United States",
                        "geolocation": {"lat": 40, "lon": -70},
                        "postalCode": "11375",
                        "state": "New York",
                    },
                    "id": "okta.1234",
                    "ipAddress": "1.2.3.4",
                    "userAgent": {
                        "browser": "SAFARI",
                        "os": "Mac OS X",
                        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
                    },
                    "zone": "null",
                },
                "debugcontext": {
                    "debugData": {
                        "authnRequestId": "yyyy-abc-1111",
                        "behaviors": "{New Geo-Location=NEGATIVE, New Device=NEGATIVE, New IP=NEGATIVE, New State=NEGATIVE, New Country=NEGATIVE, Velocity=NEGATIVE, New City=NEGATIVE}",
                        "dtHash": "11aabbccc",
                        "grantType": "authorization_code",
                        "grantedScopes": "openid, profile, email, okta.users.read.self",
                        "redirectUri": "https://org.okta.com/enduser/callback",
                        "requestId": "ABCDEFG",
                        "requestUri": "/login/token/redirect",
                        "requestedScopes": "openid, profile, email, okta.users.read.self",
                        "responseMode": "query",
                        "responseType": "code",
                        "risk": "{level=LOW}",
                        "state": "SDFJDSLFS1234",
                        "threatSuspected": "false",
                        "url": "/login/token/redirect?stateToken=02.id.ASDDFJLKF",
                        "userId": "00abc124",
                    },
                },
                "displaymessage": "OIDC authorization code request",
                "eventtype": "app.oauth2.authorize.code",
                "legacyeventtype": "app.oauth2.authorize.code_success",
                "outcome": {"result": "SUCCESS"},
                "published": "2022-12-13 15:22:58.759",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Queens",
                                "country": "United States",
                                "geolocation": {"lat": 40, "lon": -70},
                                "postalCode": "11375",
                                "state": "New York",
                            },
                            "ip": "1.2.3.4",
                            "version": "V4",
                        },
                    ],
                },
                "securitycontext": {
                    "asNumber": 701,
                    "asOrg": "verizon",
                    "domain": "verizon.net",
                    "isProxy": False,
                    "isp": "verizon",
                },
                "severity": "INFO",
                "target": [
                    {"id": "abcd123", "type": "User"},
                    {"displayName": "Authorization Code", "id": "SDFSFJL", "type": "code"},
                ],
                "transaction": {"detail": {}, "id": "SDKFLSKLFJSLF", "type": "WEB"},
                "uuid": "abc-1234-aaa",
                "version": "0",
            },
        ),
        RuleTest(
            name="Reuse Event",
            expected_result=True,
            log={
                "actor": {
                    "alternateId": "123456",
                    "displayName": "Okta User",
                    "id": "okta.1234.",
                    "type": "PublicClientApp",
                },
                "authenticationcontext": {"authenticationStep": 0, "externalSessionId": "123456789"},
                "client": {
                    "device": "Computer",
                    "geographicalContext": {
                        "city": "Queens",
                        "country": "United States",
                        "geolocation": {"lat": 40, "lon": -70},
                        "postalCode": "11375",
                        "state": "New York",
                    },
                    "id": "okta.1234",
                    "ipAddress": "1.2.3.4",
                    "userAgent": {
                        "browser": "SAFARI",
                        "os": "Mac OS X",
                        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
                    },
                    "zone": "null",
                },
                "debugcontext": {
                    "debugData": {
                        "authnRequestId": "yyyy-abc-1111",
                        "behaviors": "{New Geo-Location=NEGATIVE, New Device=NEGATIVE, New IP=NEGATIVE, New State=NEGATIVE, New Country=NEGATIVE, Velocity=NEGATIVE, New City=NEGATIVE}",
                        "dtHash": "11aabbccc",
                        "grantType": "authorization_code",
                        "grantedScopes": "openid, profile, email, okta.users.read.self",
                        "redirectUri": "https://org.okta.com/enduser/callback",
                        "requestId": "ABCDEFG",
                        "requestUri": "/login/token/redirect",
                        "requestedScopes": "openid, profile, email, okta.users.read.self",
                        "responseMode": "query",
                        "responseType": "code",
                        "risk": "{level=LOW}",
                        "state": "SDFJDSLFS1234",
                        "threatSuspected": "false",
                        "url": "/login/token/redirect?stateToken=02.id.ASDDFJLKF",
                        "userId": "00abc124",
                    },
                },
                "displaymessage": "Token Reuse",
                "eventtype": "app.oauth2.token.detect_reuse",
                "legacyeventtype": "app.oauth2.token.detect_reuse",
                "outcome": {"result": "SUCCESS"},
                "published": "2022-12-13 15:22:58.759",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Queens",
                                "country": "United States",
                                "geolocation": {"lat": 40, "lon": -70},
                                "postalCode": "11375",
                                "state": "New York",
                            },
                            "ip": "1.2.3.4",
                            "version": "V4",
                        },
                    ],
                },
                "securitycontext": {
                    "asNumber": 701,
                    "asOrg": "verizon",
                    "domain": "verizon.net",
                    "isProxy": False,
                    "isp": "verizon",
                },
                "severity": "INFO",
                "target": [
                    {"id": "abcd123", "type": "User"},
                    {"displayName": "Authorization Code", "id": "SDFSFJL", "type": "code"},
                ],
                "transaction": {"detail": {}, "id": "SDKFLSKLFJSLF", "type": "WEB"},
                "uuid": "abc-1234-aaa",
                "version": "0",
            },
        ),
    ]
