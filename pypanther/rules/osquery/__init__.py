from pypanther.rules.osquery.osquery_linux_aws_commands import (
    OsqueryLinuxAWSCommandExecuted as OsqueryLinuxAWSCommandExecuted,
)
from pypanther.rules.osquery.osquery_linux_logins_non_office import (
    OsqueryLinuxLoginFromNonOffice as OsqueryLinuxLoginFromNonOffice,
)
from pypanther.rules.osquery.osquery_linux_mac_vulnerable_xz_liblzma import (
    OsqueryLinuxMacVulnerableXZliblzma as OsqueryLinuxMacVulnerableXZliblzma,
)
from pypanther.rules.osquery.osquery_mac_application_firewall import (
    OsqueryMacApplicationFirewallSettings as OsqueryMacApplicationFirewallSettings,
)
from pypanther.rules.osquery.osquery_mac_enable_auto_update import (
    OsqueryMacAutoUpdateEnabled as OsqueryMacAutoUpdateEnabled,
)
from pypanther.rules.osquery.osquery_mac_osx_attacks import OsqueryMacOSXAttacks as OsqueryMacOSXAttacks
from pypanther.rules.osquery.osquery_mac_osx_attacks_keyboard_events import (
    OsqueryMacOSXAttacksKeyboardEvents as OsqueryMacOSXAttacksKeyboardEvents,
)
from pypanther.rules.osquery.osquery_mac_unwanted_chrome_extensions import (
    OsqueryMacUnwantedChromeExtensions as OsqueryMacUnwantedChromeExtensions,
)
from pypanther.rules.osquery.osquery_ossec import OsqueryOSSECRootkitDetected as OsqueryOSSECRootkitDetected
from pypanther.rules.osquery.osquery_outdated import OsqueryOutdatedAgent as OsqueryOutdatedAgent
from pypanther.rules.osquery.osquery_outdated_macos import OsqueryUnsupportedMacOS as OsqueryUnsupportedMacOS
from pypanther.rules.osquery.osquery_ssh_listener import OsquerySSHListener as OsquerySSHListener
from pypanther.rules.osquery.osquery_suspicious_cron import OsquerySuspiciousCron as OsquerySuspiciousCron
