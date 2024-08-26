from pypanther.rules.okta.okta_account_support_access import OktaSupportAccess as OktaSupportAccess
from pypanther.rules.okta.okta_account_support_access import okta_support_access_tests as okta_support_access_tests
from pypanther.rules.okta.okta_admin_disabled_mfa import OktaGlobalMFADisabled as OktaGlobalMFADisabled
from pypanther.rules.okta.okta_admin_disabled_mfa import (
    okta_global_mfa_disabled_tests as okta_global_mfa_disabled_tests,
)
from pypanther.rules.okta.okta_admin_role_assigned import OktaAdminRoleAssigned as OktaAdminRoleAssigned
from pypanther.rules.okta.okta_admin_role_assigned import (
    okta_admin_role_assigned_tests as okta_admin_role_assigned_tests,
)
from pypanther.rules.okta.okta_anonymizing_vpn_login import OktaAnonymizingVPNLogin as OktaAnonymizingVPNLogin
from pypanther.rules.okta.okta_anonymizing_vpn_login import (
    okta_anonymizing_vpn_login_tests as okta_anonymizing_vpn_login_tests,
)
from pypanther.rules.okta.okta_api_key_created import OktaAPIKeyCreated as OktaAPIKeyCreated
from pypanther.rules.okta.okta_api_key_created import okta_api_key_created_tests as okta_api_key_created_tests
from pypanther.rules.okta.okta_api_key_revoked import OktaAPIKeyRevoked as OktaAPIKeyRevoked
from pypanther.rules.okta.okta_api_key_revoked import okta_api_key_revoked_tests as okta_api_key_revoked_tests
from pypanther.rules.okta.okta_app_refresh_access_token_reuse import (
    OktaRefreshAccessTokenReuse as OktaRefreshAccessTokenReuse,
)
from pypanther.rules.okta.okta_app_refresh_access_token_reuse import (
    okta_refresh_access_token_reuse_tests as okta_refresh_access_token_reuse_tests,
)
from pypanther.rules.okta.okta_app_unauthorized_access_attempt import (
    OktaAppUnauthorizedAccessAttempt as OktaAppUnauthorizedAccessAttempt,
)
from pypanther.rules.okta.okta_app_unauthorized_access_attempt import (
    okta_app_unauthorized_access_attempt_tests as okta_app_unauthorized_access_attempt_tests,
)
from pypanther.rules.okta.okta_group_admin_role_assigned import OktaGroupAdminRoleAssigned as OktaGroupAdminRoleAssigned
from pypanther.rules.okta.okta_group_admin_role_assigned import (
    okta_group_admin_role_assigned_tests as okta_group_admin_role_assigned_tests,
)
from pypanther.rules.okta.okta_idp_create_modify import (
    OktaIdentityProviderCreatedModified as OktaIdentityProviderCreatedModified,
)
from pypanther.rules.okta.okta_idp_create_modify import (
    okta_identity_provider_created_modified_tests as okta_identity_provider_created_modified_tests,
)
from pypanther.rules.okta.okta_idp_signin import OktaIdentityProviderSignIn as OktaIdentityProviderSignIn
from pypanther.rules.okta.okta_idp_signin import (
    okta_identity_provider_sign_in_tests as okta_identity_provider_sign_in_tests,
)
from pypanther.rules.okta.okta_login_signal import OktaLoginSuccess as OktaLoginSuccess
from pypanther.rules.okta.okta_login_signal import okta_login_success_tests as okta_login_success_tests
from pypanther.rules.okta.okta_login_without_push_marker import OktaLoginWithoutPushMarker as OktaLoginWithoutPushMarker
from pypanther.rules.okta.okta_login_without_push_marker import (
    okta_login_without_push_marker_tests as okta_login_without_push_marker_tests,
)
from pypanther.rules.okta.okta_new_behavior_accessing_admin_console import (
    OktaNewBehaviorAccessingAdminConsole as OktaNewBehaviorAccessingAdminConsole,
)
from pypanther.rules.okta.okta_new_behavior_accessing_admin_console import (
    okta_new_behavior_accessing_admin_console_tests as okta_new_behavior_accessing_admin_console_tests,
)
from pypanther.rules.okta.okta_org2org_creation_modification import (
    OktaOrg2orgCreationModification as OktaOrg2orgCreationModification,
)
from pypanther.rules.okta.okta_org2org_creation_modification import (
    okta_org2org_creation_modification_tests as okta_org2org_creation_modification_tests,
)
from pypanther.rules.okta.okta_password_accessed import OktaPasswordAccess as OktaPasswordAccess
from pypanther.rules.okta.okta_password_accessed import okta_password_access_tests as okta_password_access_tests
from pypanther.rules.okta.okta_password_extraction_via_scim import (
    OktaPasswordExtractionviaSCIM as OktaPasswordExtractionviaSCIM,
)
from pypanther.rules.okta.okta_password_extraction_via_scim import (
    okta_password_extractionvia_scim_tests as okta_password_extractionvia_scim_tests,
)
from pypanther.rules.okta.okta_phishing_attempt_blocked_by_fastpass import (
    OktaPhishingAttemptBlockedFastPass as OktaPhishingAttemptBlockedFastPass,
)
from pypanther.rules.okta.okta_phishing_attempt_blocked_by_fastpass import (
    okta_phishing_attempt_blocked_fast_pass_tests as okta_phishing_attempt_blocked_fast_pass_tests,
)
from pypanther.rules.okta.okta_potentially_stolen_session import (
    OktaPotentiallyStolenSession as OktaPotentiallyStolenSession,
)
from pypanther.rules.okta.okta_potentially_stolen_session import (
    okta_potentially_stolen_session_tests as okta_potentially_stolen_session_tests,
)
from pypanther.rules.okta.okta_rate_limits import OktaRateLimits as OktaRateLimits
from pypanther.rules.okta.okta_rate_limits import okta_rate_limits_tests as okta_rate_limits_tests
from pypanther.rules.okta.okta_sso_to_aws import OktaSSOtoAWS as OktaSSOtoAWS
from pypanther.rules.okta.okta_sso_to_aws import okta_ss_oto_aws_tests as okta_ss_oto_aws_tests
from pypanther.rules.okta.okta_support_reset import OktaSupportReset as OktaSupportReset
from pypanther.rules.okta.okta_support_reset import okta_support_reset_tests as okta_support_reset_tests
from pypanther.rules.okta.okta_threatinsight_security_threat_detected import (
    OktaThreatInsightSecurityThreatDetected as OktaThreatInsightSecurityThreatDetected,
)
from pypanther.rules.okta.okta_threatinsight_security_threat_detected import (
    okta_threat_insight_security_threat_detected_tests as okta_threat_insight_security_threat_detected_tests,
)
from pypanther.rules.okta.okta_user_account_locked import OktaUserAccountLocked as OktaUserAccountLocked
from pypanther.rules.okta.okta_user_account_locked import (
    okta_user_account_locked_tests as okta_user_account_locked_tests,
)
from pypanther.rules.okta.okta_user_mfa_factor_suspend import OktaUserMFAFactorSuspend as OktaUserMFAFactorSuspend
from pypanther.rules.okta.okta_user_mfa_factor_suspend import (
    okta_user_mfa_factor_suspend_tests as okta_user_mfa_factor_suspend_tests,
)
from pypanther.rules.okta.okta_user_mfa_reset import OktaUserMFAResetSingle as OktaUserMFAResetSingle
from pypanther.rules.okta.okta_user_mfa_reset import (
    okta_user_mfa_reset_single_tests as okta_user_mfa_reset_single_tests,
)
from pypanther.rules.okta.okta_user_mfa_reset_all import OktaUserMFAResetAll as OktaUserMFAResetAll
from pypanther.rules.okta.okta_user_mfa_reset_all import okta_user_mfa_reset_all_tests as okta_user_mfa_reset_all_tests
from pypanther.rules.okta.okta_user_reported_suspicious_activity import (
    OktaUserReportedSuspiciousActivity as OktaUserReportedSuspiciousActivity,
)
from pypanther.rules.okta.okta_user_reported_suspicious_activity import (
    okta_user_reported_suspicious_activity_tests as okta_user_reported_suspicious_activity_tests,
)
