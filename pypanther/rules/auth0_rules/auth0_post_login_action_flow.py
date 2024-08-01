from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_auth0_helpers import auth0_alert_context, is_auth0_config_event
from pypanther.helpers.panther_base_helpers import deep_get

auth0_post_login_action_flow_tests: list[RuleTest] = [
    RuleTest(
        name="Other Event",
        expected_result=False,
        log={
            "data": {
                "client_id": "XXX",
                "client_name": "",
                "date": "2023-05-16 17:28:11.165000000",
                "description": "Set the Multi-factor Authentication policies",
                "details": {
                    "request": {
                        "auth": {
                            "credentials": {
                                "jti": "XXX",
                                "scopes": ["create:actions", "update:triggers", "update:users"],
                            },
                            "strategy": "jwt",
                            "user": {
                                "email": "user.name@yourcompany.io",
                                "name": "User Name",
                                "user_id": "google-oauth2|XXX",
                            },
                        },
                        "body": [],
                        "channel": "https://manage.auth0.com/",
                        "ip": "12.12.12.12",
                        "method": "put",
                        "path": "/api/v2/guardian/policies",
                        "query": {},
                        "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
                    },
                    "response": {"body": [], "statusCode": 200},
                },
                "ip": "12.12.12.12",
                "log_id": "XXX",
                "type": "sapi",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
                "user_id": "google-oauth2|XXX",
            },
            "log_id": "XXX",
            "p_source_label": "Org Tenant Label",
        },
    ),
    RuleTest(
        name="Action Added",
        expected_result=True,
        log={
            "data": {
                "client_id": "XXX",
                "client_name": "",
                "date": "2023-05-23 20:53:36.557000000",
                "description": "Update trigger bindings",
                "details": {
                    "request": {
                        "auth": {
                            "credentials": {"jti": "XXX"},
                            "strategy": "jwt",
                            "user": {
                                "email": "homer.simpson@yourcompany.com",
                                "name": "Homer Simpson",
                                "user_id": "google-oauth2|XXX",
                            },
                        },
                        "body": {
                            "bindings": [
                                {"display_name": "Password Rotation", "ref": {"type": "action_id", "value": "XXX"}},
                            ],
                        },
                        "channel": "https://manage.auth0.com/",
                        "ip": "12.12.12.12",
                        "method": "patch",
                        "path": "/api/v2/actions/triggers/post-login/bindings",
                        "query": {},
                        "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
                    },
                    "response": {
                        "body": {
                            "bindings": [
                                {
                                    "action": {
                                        "all_changes_deployed": False,
                                        "created_at": "2023-04-24T19:33:44.217168082Z",
                                        "current_version": {
                                            "created_at": "2023-05-11T17:26:53.569382908Z",
                                            "id": "c4c1d580-2f51-4d7b-afa5-ad4216f40ad3",
                                            "runtime": "node16",
                                            "status": "BUILT",
                                            "updated_at": "2023-05-11T17:26:53.724617041Z",
                                        },
                                        "deployed_version": {
                                            "code": "",
                                            "created_at": "2023-05-11T17:26:53.569382908Z",
                                            "dependencies": [],
                                            "deployed": True,
                                            "id": "c4c1d580-2f51-4d7b-afa5-ad4216f40ad3",
                                            "runtime": "node16",
                                            "secrets": [],
                                            "status": "built",
                                            "updated_at": "2023-05-11T17:26:53.724617041Z",
                                        },
                                        "id": "XXX",
                                        "installed_integration_id": "XXX",
                                        "integration": {
                                            "catalog_id": "password-rotation",
                                            "created_at": "2023-04-24T19:33:44.212805393Z",
                                            "current_release": {"id": "", "semver": {}},
                                            "description": "This Action allows you to configure the number of days a password is valid before it expires and the user must rotate it.\n",
                                            "feature_type": "action",
                                            "id": "64bee519-818f-4473-ab08-7c380f28da77",
                                            "logo": "https://cdn.auth0.com/marketplace/catalog/content/assets/creators/auth0/auth0-avatar.png",
                                            "name": "Password Rotation",
                                            "partner_id": "XXX",
                                            "short_description": "Enforce Users to Rotate Passwords",
                                            "terms_of_use_url": "https://cdn.auth0.com/website/legal/files/mktplace/auth0-integration.pdf",
                                            "updated_at": "2023-05-11T17:26:53.560940001Z",
                                            "url_slug": "auth-0-password-rotation",
                                        },
                                        "name": "Password Rotation v1",
                                        "supported_triggers": [
                                            {"id": "post-login", "status": "CURRENT", "version": "v3"},
                                        ],
                                        "updated_at": "2023-04-24T19:33:44.217168082Z",
                                    },
                                    "created_at": "2023-05-23T20:53:36.528608347Z",
                                    "display_name": "Password Rotation",
                                    "id": "a12b9e2a-ec0f-4060-b476-18547030088a",
                                    "trigger_id": "post-login",
                                    "updated_at": "2023-05-23T20:53:36.528608347Z",
                                },
                            ],
                        },
                        "statusCode": 200,
                    },
                },
                "ip": "12.12.12.12",
                "log_id": "XXX",
                "type": "sapi",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
                "user_id": "google-oauth2|XXX",
            },
            "log_id": "XXX",
            "p_source_label": "Org Auth0 Tenant Label",
        },
    ),
    RuleTest(
        name="Action Removed",
        expected_result=True,
        log={
            "data": {
                "client_id": "XXX",
                "client_name": "",
                "date": "2023-05-23 21:35:54.491000000",
                "description": "Update trigger bindings",
                "details": {
                    "request": {
                        "auth": {
                            "credentials": {"jti": "e6343ec1d24a41e6bd43a6be748cac11"},
                            "strategy": "jwt",
                            "user": {
                                "email": "homer.simpson@yourcompany.com",
                                "name": "Homer Simpson",
                                "user_id": "google-oauth2|XXX",
                            },
                        },
                        "body": {"bindings": [{"ref": {"type": "binding_id", "value": "XXX"}}]},
                        "channel": "https://manage.auth0.com/",
                        "ip": "12.12.12.12",
                        "method": "patch",
                        "path": "/api/v2/actions/triggers/post-login/bindings",
                        "query": {},
                        "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
                    },
                    "response": {
                        "body": {
                            "bindings": [
                                {
                                    "action": {
                                        "all_changes_deployed": False,
                                        "created_at": "2022-05-26T20:45:09.128843683Z",
                                        "current_version": {
                                            "created_at": "2022-05-26T20:45:09.128849956Z",
                                            "id": "XXX",
                                            "runtime": "node12",
                                            "status": "BUILT",
                                            "updated_at": "2022-05-26T20:45:32.857727217Z",
                                        },
                                        "deployed_version": {
                                            "code": "",
                                            "created_at": "2022-05-26T20:45:09.128849956Z",
                                            "dependencies": [],
                                            "deployed": True,
                                            "id": "XXX",
                                            "runtime": "node12",
                                            "secrets": [],
                                            "status": "built",
                                            "updated_at": "2022-05-26T20:45:32.857727217Z",
                                        },
                                        "id": "XXX",
                                        "installed_integration_id": "XXX",
                                        "integration": {
                                            "catalog_id": "auth0-country-based-access",
                                            "created_at": "2022-05-26T20:45:09.064825654Z",
                                            "current_release": {"id": "", "semver": {}},
                                            "description": "This integration allows you to restrict access to your applications by country. You may choose to implement Country-based Access controls for various reasons, including to allow your applications to comply with unique restrictions based on where you do business. \n\nWith the Country-based Access integration, you can define any and all countries to restrict persons and entities from those countries logging into your applications. ",
                                            "feature_type": "action",
                                            "id": "XXX",
                                            "logo": "https://cdn.auth0.com/marketplace/catalog/content/assets/creators/auth0/auth0-avatar.png",
                                            "name": "Country-based Access",
                                            "partner_id": "XXX",
                                            "public_support_link": "https://support.auth0.com/",
                                            "short_description": "Restrict access to users by country",
                                            "terms_of_use_url": "https://cdn.auth0.com/website/legal/files/mktplace/auth0-integration.pdf",
                                            "updated_at": "2022-05-26T20:45:09.064825654Z",
                                            "url_slug": "country-based-access",
                                        },
                                        "name": "Country-based Access v2",
                                        "supported_triggers": [
                                            {"id": "post-login", "status": "CURRENT", "version": "v2"},
                                        ],
                                        "updated_at": "2022-05-26T20:45:09.128843683Z",
                                    },
                                    "created_at": "2023-05-23T21:35:47.983852439Z",
                                    "display_name": "Country-based Access",
                                    "id": "XXX",
                                    "trigger_id": "post-login",
                                    "updated_at": "2023-05-23T21:35:54.464801212Z",
                                },
                            ],
                        },
                        "statusCode": 200,
                    },
                },
                "ip": "12.12.12.12",
                "log_id": "XXX",
                "type": "sapi",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
                "user_id": "google-oauth2|XXX",
            },
            "log_id": "XXX",
            "p_source_label": "Org Auth0 Tenant Label",
        },
    ),
    RuleTest(
        name="All Actions Removed",
        expected_result=True,
        log={
            "data": {
                "client_id": "XXX",
                "client_name": "",
                "date": "2023-05-23 21:28:56.071000000",
                "description": "Update trigger bindings",
                "details": {
                    "request": {
                        "auth": {
                            "credentials": {"jti": "XXX"},
                            "strategy": "jwt",
                            "user": {
                                "email": "homer.simpson@yourcompany.com",
                                "name": "Homer Simpson",
                                "user_id": "google-oauth2|XXX",
                            },
                        },
                        "body": {"bindings": []},
                        "channel": "https://manage.auth0.com/",
                        "ip": "12.12.12.12",
                        "method": "patch",
                        "path": "/api/v2/actions/triggers/post-login/bindings",
                        "query": {},
                        "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
                    },
                    "response": {"body": {"bindings": []}, "statusCode": 200},
                },
                "ip": "12.12.12.12",
                "log_id": "XXX",
                "type": "sapi",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
                "user_id": "google-oauth2|XXX",
            },
            "log_id": "XXX",
            "p_source_label": "Org Auth0 Tenant Label",
        },
    ),
]


@panther_managed
class Auth0PostLoginActionFlow(Rule):
    default_description = "An Auth0 User updated a post login action flow for your organization's tenant."
    display_name = "Auth0 Post Login Action Flow Updated"
    default_runbook = "Assess if this was done by the user for a valid business reason. Be sure to replace any steps that were removed without authorization."
    default_reference = "https://auth0.com/docs/customize/actions/flows-and-triggers/login-flow/api-object"
    default_severity = Severity.MEDIUM
    log_types = [LogType.AUTH0_EVENTS]
    id = "Auth0.Post.Login.Action.Flow-prototype"
    tests = auth0_post_login_action_flow_tests

    def rule(self, event):
        data_description = deep_get(event, "data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")
        request_path = deep_get(event, "data", "details", "request", "path", default="<NO_REQUEST_PATH_FOUND>")
        return all(
            [
                data_description == "Update trigger bindings",
                request_path == "/api/v2/actions/triggers/post-login/bindings",
                is_auth0_config_event(event),
            ],
        )

    def title(self, event):
        user = deep_get(event, "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>")
        p_source_label = deep_get(event, "p_source_label", default="<NO_P_SOURCE_LABEL_FOUND>")
        request_bindings = deep_get(event, "data", "details", "request", "body", "bindings", default=[])
        response_bindings = deep_get(event, "data", "details", "response", "body", "bindings", default=[])
        actions_added_list = []
        for binding in request_bindings:
            if "display_name" in binding:
                # check to see if actions were added to the flow
                actions_added_list.append(binding.get("display_name", ""))
        # otherwise, actions were removed from the action flow and we want
        # to grab what's still present in the flow
        actions_remaining_list = []
        for binding in response_bindings:
            if deep_get(binding, "display_name"):
                actions_remaining_list.append(deep_get(binding, "display_name", default="<NO_DISPLAYNAME>"))
        if actions_added_list:
            return f"Auth0 User [{user}] added action(s) [{actions_added_list}] to a post-login action flow for your organization’s tenant [{p_source_label}]."
        if actions_remaining_list:
            return f"Auth0 User [{user}] removed action(s) to a post-login action flow for your organization’s tenant [{p_source_label}], remaining actions include [{actions_remaining_list}]."
        # no actions remain in the flow
        return f"Auth0 User [{user}] removed all actions from a post-login action flow for your organization’s tenant [{p_source_label}]."

    def alert_context(self, event):
        return auth0_alert_context(event)
