#
# Cookbook:: wintel-2019
# Recipe:: computer
#
# Copyright:: 2022, The Authors, All Rights Reserved.

# Allow Online Tips

registry_key node['windows']['Policy']['AllowOnlineTips'] do
  values [{
    name: 'AllowOnlineTips',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Settings Page Visibility

registry_key node['windows']['Policy']['SettingsPageVisibility'] do
  values [{
    name: 'SettingsPageVisibility',
    type: :string,
    data: 'showonly:about',
  }]
  recursive true
  action :create
end

# Prevent enabling lock screen camera

registry_key node['windows']['Policy']['NoLockScreenCamera'] do
  values [{
    name: 'NoLockScreenCamera',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prevent enabling lock screen slide show

registry_key node['windows']['Policy']['NoLockScreenSlideshow'] do
  values [{
    name: 'NoLockScreenSlideshow',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow users to enable online speech recognition services

registry_key node['windows']['Policy']['AllowInputPersonalization'] do
  values [{
    name: 'AllowInputPersonalization',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Do not allow password expiration time longer than required by policy

registry_key node['windows']['Policy']['PwdExpirationProtectionEnabled'] do
  values [{
    name: 'PwdExpirationProtectionEnabled',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Enable local admin password management

registry_key node['windows']['Policy']['AdmPwdEnabled'] do
  values [{
    name: 'AdmPwdEnabled',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Apply UAC restrictions to local accounts on network logons

registry_key node['windows']['Policy']['LocalAccountTokenFilterPolicy'] do
  values [{
    name: 'LocalAccountTokenFilterPolicy',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Block Flash activation in Office documents

registry_key node['windows']['Policy']['Comment'] do
  values [{
    name: 'Comment',
    type: :string,
    data: 'Block All Activation',
  }]
  recursive true
  action :create
end

# Configure SMB v1 client driver

registry_key node['windows']['Policy']['Start'] do
  values [{
    name: 'Start',
    type: :dword,
    data: 4,
  }]
  recursive true
  action :create
end

# Configure SMB v2 client driver

registry_key node['windows']['Policy']['Start20'] do
  values [{
    name: 'Start',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Configure SMB v1 server

registry_key node['windows']['Policy']['SMB1'] do
  values [{
    name: 'SMB1',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Configure SMB v2 server

registry_key node['windows']['Policy']['SMB2'] do
  values [{
    name: 'SMB2',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Enable Structured Exception Handling Overwrite Protection (SEHOP)

registry_key node['windows']['Policy']['DisableExceptionChainValidation'] do
  values [{
    name: 'DisableExceptionChainValidation',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Extended Protection for LDAP Authentication (Domain Controllers only)

registry_key node['windows']['Policy']['LdapEnforceChannelBinding'] do
  values [{
    name: 'LdapEnforceChannelBinding',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# LSA Protection

registry_key node['windows']['Policy']['RunAsPPL'] do
  values [{
    name: 'RunAsPPL',
    type: :dword,
    data: 00000001,
  }]
  recursive true
  action :create
end

# Lsass.exe audit mode

registry_key node['windows']['Policy']['AuditLevel'] do
  values [{
    name: 'AuditLevel',
    type: :dword,
    data: 8,
  }]
  recursive true
  action :create
end

# Remove "Run As Different User" from context menus

registry_key node['windows']['Policy']['ShowRunAsDifferentUserInStart'] do
  values [{
    name: 'ShowRunAsDifferentUserInStart',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# WDigest Authentication (disabling may require KB2871997)

registry_key node['windows']['Policy']['UseLogonCredential'] do
  values [{
    name: 'UseLogonCredential',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)

registry_key node['windows']['Policy']['AutoAdminLogon'] do
  values [{
    name: 'AutoAdminLogon',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# MSS: (AutoReboot) Allow Windows to automatically restart after a system crash (recommended except for highly secure environments)

registry_key node['windows']['Policy']['AutoReboot'] do
  values [{
    name: 'AutoReboot',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# MSS: (AutoShareServer) Enable Administrative Shares (recommended except for highly secure environments)

registry_key node['windows']['Policy']['AutoShareServer'] do
  values [{
    name: 'AutoShareServer',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)

registry_key node['windows']['Policy']['IPv6']['DisableIPSourceRouting'] do
  values [{
    name: 'DisableIPSourceRouting',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)

registry_key node['windows']['Policy']['IPv4']['DisableIPSourceRouting'] do
  values [{
    name: 'DisableIPSourceRouting',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# MSS: (DisableSavePassword) Prevent the dial-up passsword from being saved (recommended)

registry_key node['windows']['Policy']['DisableSavePassword'] do
  values [{
    name: 'DisableSavePassword',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# MSS: (EnableDeadGWDetect) Allow automatic detection of dead network gateways (could lead to DoS)

registry_key node['windows']['Policy']['EnableDeadGWDetect'] do
  values [{
    name: 'EnableDeadGWDetect',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes

registry_key node['windows']['Policy']['EnableICMPRedirect'] do
  values [{
    name: 'EnableICMPRedirect',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# MSS: (Hidden) Hide Computer From the Browse List (not recommended except for highly secure environments)

registry_key node['windows']['Policy']['Hidden'] do
  values [{
    name: 'Hidden',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds

registry_key node['windows']['Policy']['KeepAliveTime'] do
  values [{
    name: 'KeepAliveTime',
    type: :dword,
    data: 300000,
  }]
  recursive true
  action :create
end

# MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers

registry_key node['windows']['Policy']['NoNameReleaseOnDemand'] do
  values [{
    name: 'NoNameReleaseOnDemand',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# MSS: (NtfsDisable8dot3NameCreation) Enable the computer to stop generating 8.3 style filenames

registry_key node['windows']['Policy']['ntfsdisable'] do
  values [{
    name: 'NtfsDisable8dot3NameCreation',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)

registry_key node['windows']['Policy']['PerformRouterDiscovery'] do
  values [{
    name: 'PerformRouterDiscovery',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)

registry_key node['windows']['Policy']['SafeDllSearchMode'] do
  values [{
    name: 'SafeDllSearchMode',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)

registry_key node['windows']['Policy']['ScreenSaverGracePeriod'] do
  values [{
    name: 'ScreenSaverGracePeriod',
    type: :string,
    data: 0,
  }]
  recursive true
  action :create
end

# MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)

registry_key node['windows']['Policy']['IPv6']['TcpMaxDataRetransmissions'] do
  values [{
    name: 'TcpMaxDataRetransmissions',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)

registry_key node['windows']['Policy']['IPv4']['TcpMaxDataRetransmissions'] do
  values [{
    name: 'TcpMaxDataRetransmissions',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning

registry_key node['windows']['Policy']['WarningLevel'] do
  values [{
    name: 'WarningLevel',
    type: :dword,
    data: 80,
  }]
  recursive true
  action :create
end

# Turn off multicast name resolution

registry_key node['windows']['Policy']['EnableMulticast'] do
  values [{
    name: 'EnableMulticast',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Enable Font Providers

registry_key node['windows']['Policy']['EnableFontProviders'] do
  values [{
    name: 'EnableFontProviders',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Enable Hotspot Authentication

registry_key node['windows']['Policy']['Hotspot']['Enabled'] do
  values [{
    name: 'Enabled',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Network\Lanman Server - Cipher suite order

registry_key node['windows']['Policy']['Server']['CipherSuiteOrder'] do
  values [{
    name: 'CipherSuiteOrder',
    type: :multi_string,
    data: %w(),
  }]
  recursive true
  action :create
end

# Set LanManWorkstation Dependencies

registry_key node['windows']['Policy']['DependOnService'] do
  values [{
    name: 'DependOnService',
    type: :multi_string,
    data: %w(Bowser MRxSmb20 NSI),
  }]
  recursive true
  action :create
end

# Network\Lanman Server - Honor cipher suite order

registry_key node['windows']['Policy']['HonorCipherSuiteOrder'] do
  values [{
    name: 'HonorCipherSuiteOrder',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Network\Lanman Workstation : Cipher suite order

registry_key node['windows']['Policy']['Workstation']['CipherSuiteOrder'] do
  values [{
    name: 'CipherSuiteOrder',
    type: :multi_string,
    data: %w(),
  }]
  recursive true
  action :create
end

# Enable insecure guest logons

registry_key node['windows']['Policy']['AllowInsecureGuestAuth'] do
  values [{
    name: 'AllowInsecureGuestAuth',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on Mapper I/O (LLTDIO) driver

registry_key node['windows']['Policy']['LLTD']['Path'] do
  values [{
    name: 'EnableLLTDIO',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['LLTD']['Path'] do
  values [{
    name: 'AllowLLTDIOOnDomain',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['LLTD']['Path'] do
  values [{
    name: 'AllowLLTDIOOnPublicNet',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['LLTD']['Path'] do
  values [{
    name: 'ProhibitLLTDIOOnPrivateNet',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on Responder (RSPNDR) driver

registry_key node['windows']['Policy']['LLTD']['Path'] do
  values [{
    name: 'EnableRspndr',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['LLTD']['Path'] do
  values [{
    name: 'AllowRspndrOnDomain',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['LLTD']['Path'] do
  values [{
    name: 'AllowRspndrOnPublicNet',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['LLTD']['Path'] do
  values [{
    name: 'ProhibitRspndrOnPrivateNet',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Disable password strength validation for Peer Grouping

registry_key node['windows']['Policy']['IgnoreDomainPasswordPolicyForNewGroups'] do
  values [{
    name: 'IgnoreDomainPasswordPolicyForNewGroups',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off Microsoft Peer-to-Peer Networking Services

registry_key node['windows']['Policy']['Disabled'] do
  values [{
    name: 'Disabled',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prohibit installation and configuration of Network Bridge on your DNS domain network

registry_key node['windows']['Policy']['NC_AllowNetBridge_NLA'] do
  values [{
    name: 'NC_AllowNetBridge_NLA',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Prohibit use of Internet Connection Firewall on your DNS domain network

registry_key node['windows']['Policy']['NC_PersonalFirewallConfig'] do
  values [{
    name: 'NC_PersonalFirewallConfig',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Prohibit use of Internet Connection Sharing on your DNS domain network

registry_key node['windows']['Policy']['NC_ShowSharedAccessUI'] do
  values [{
    name: 'NC_ShowSharedAccessUI',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Require domain users to elevate when setting a network's location

registry_key node['windows']['Policy']['NC_StdDomainUserSetLocation'] do
  values [{
    name: 'NC_StdDomainUserSetLocation',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Route all traffic through the internal network

registry_key node['windows']['Policy']['Force_Tunneling'] do
  values [{
    name: 'ForceTunneling',
    type: :string,
    data: 'Disabled',
  }]
  recursive true
  action :create
end

# Hardened UNC Paths

registry_key node['windows']['Policy']['HardenedPaths'] do
  values [{ name: '\\*\SYSVOL', type: :string, data: 'RequireMutualAuthentication=1,RequireIntegrity=1' },
          { name: '\\*\NETLOGON', type: :string, data: 'RequireMutualAuthentication=1,RequireIntegrity=1' },
         ]
  action :create
  recursive true
end

# Allow or Disallow use of the Offline Files feature

registry_key node['windows']['Policy']['NetCache'] do
  values [{
    name: 'Enabled',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# ECC Curve Order

registry_key node['windows']['Policy']['EccCurves'] do
  values [{
    name: 'EccCurves',
    type: :multi_string,
    data: %w(),
  }]
  recursive true
  action :create
end

# SSL Cipher Suite Order ### Need to Check

registry_key node['windows']['Policy']['Functions'] do
  values [{
    name: 'Functions',
    type: :string,
    data: 'LS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  }]
  recursive true
  action :create
end

# Set 6to4 Relay Name

registry_key node['windows']['Policy']['6to4_RouterName'] do
  values [{
    name: '6to4_RouterName',
    type: :string,
    data: '',
  }]
  recursive true
  action :create
end

# Set 6to4 Relay Name Resolution Interval

registry_key node['windows']['Policy']['6to4_RouterNameResolutionInterval'] do
  values [{
    name: '6to4_RouterNameResolutionInterval',
    type: :string,
    data: '',
  }]
  recursive true
  action :create
end

# Set 6to4 State

registry_key node['windows']['Policy']['6to4_State'] do
  values [{
    name: '6to4_State',
    type: :string,
    data: 'Disabled',
  }]
  recursive true
  action :create
end

# Set IP-HTTPS State

registry_key node['windows']['Policy']['IPHTTPS'] do
  values [{ name: 'IPHTTPS_ClientUrl', type: :string, data: '' },
          { name: 'IPHTTPS_ClientState', type: :dword, data: '3' },
         ]
  action :create
  recursive true
end

# Set ISATAP Router Name

registry_key node['windows']['Policy']['ISATAP_RouterName'] do
  values [{
    name: 'ISATAP_RouterName',
    type: :string,
    data: '',
  }]
  recursive true
  action :create
end

# Set ISATAP State

registry_key node['windows']['Policy']['ISATAP_State'] do
  values [{
    name: 'ISATAP_State',
    type: :string,
    data: 'Disabled',
  }]
  recursive true
  action :create
end

# Set Teredo Client Port

registry_key node['windows']['Policy']['Teredo_ClientPort'] do
  values [{
    name: 'Teredo_ClientPort',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Set Teredo Default Qualified

registry_key node['windows']['Policy']['Teredo_DefaultQualified'] do
  values [{
    name: 'Teredo_DefaultQualified',
    type: :string,
    data: '',
  }]
  recursive true
  action :create
end

# Set Teredo Refresh Rate

registry_key node['windows']['Policy']['Teredo_RefreshRate'] do
  values [{
    name: 'Teredo_RefreshRate',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Set Teredo Server Name

registry_key node['windows']['Policy']['Teredo_ServerName'] do
  values [{
    name: 'Teredo_ServerName',
    type: :string,
    data: '',
  }]
  recursive true
  action :create
end

# Set Teredo State

registry_key node['windows']['Policy']['Teredo_State'] do
  values [{
    name: 'Teredo_State',
    type: :string,
    data: 'Disabled',
  }]
  recursive true
  action :create
end

# Configuration of wireless settings using Windows Connect Now

registry_key node['windows']['Policy']['EnableRegistrars'] do
  values [{
    name: 'EnableRegistrars',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Prohibit access of the Windows Connect Now wizards

registry_key node['windows']['Policy']['DisableWcnUi'] do
  values [{
    name: 'DisableWcnUi',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Minimize the number of simultaneous connections to the Internet or a Windows Domain

registry_key node['windows']['Policy']['fMinimizeConnections'] do
  values [{
    name: 'fMinimizeConnections',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prohibit connection to non-domain networks when connected to domain authenticated network

registry_key node['windows']['Policy']['fBlockNonDomain'] do
  values [{
    name: 'fBlockNonDomain',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prohibit connection to roaming Mobile Broadband networks

registry_key node['windows']['Policy']['fBlockRoaming'] do
  values [{
    name: 'fBlockRoaming',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services

registry_key node['windows']['Policy']['AutoConnectAllowedOEM'] do
  values [{
    name: 'AutoConnectAllowedOEM',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Let Windows apps access cellular data

registry_key node['windows']['Policy']['LetAppsAccessCellularData'] do
  values [{
    name: 'LetAppsAccessCellularData',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Turn off notifications network usage

registry_key node['windows']['Policy']['NoCloudApplicationNotification'] do
  values [{
    name: 'NoCloudApplicationNotification',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Enable App-V Client

registry_key node['windows']['Policy']['AppV'] do
  values [{
    name: 'Enabled',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Include command line in process creation events

registry_key node['windows']['Policy']['ProcessCreationIncludeCmdLine_Enabled'] do
  values [{
    name: 'ProcessCreationIncludeCmdLine_Enabled',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Encryption Oracle Remediation

registry_key node['windows']['Policy']['AllowEncryptionOracle'] do
  values [{
    name: 'AllowEncryptionOracle',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Remote host allows delegation of non-exportable credentials

registry_key node['windows']['Policy']['AllowProtectedCreds'] do
  values [{
    name: 'AllowProtectedCreds',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Restrict delegation of credentials to remote servers

registry_key node['windows']['Policy']['RestrictedRemoteAdministrationType'] do
  values [{
    name: 'RestrictedRemoteAdministrationType',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Turn On Virtualization Based Security

registry_key node['windows']['Policy']['DeviceGuard'] do
  values [{
    name: 'EnableVirtualizationBasedSecurity',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn On Virtualization Based Security - Virtualization Based Protection of Code Integrity

registry_key node['windows']['Policy']['DeviceGuard'] do
  values [{
    name: 'HypervisorEnforcedCodeIntegrity',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn On Virtualization Based Security - Secure Launch Configuration

registry_key node['windows']['Policy']['DeviceGuard'] do
  values [{
    name: 'ConfigureSystemGuardLaunch',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn On Virtualization Based Security - Require UEFI Memory Attributes Table

registry_key node['windows']['Policy']['DeviceGuard'] do
  values [{
    name: 'HVCIMATRequired',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn On Virtualization Based Security - Credential Guard Configuration

registry_key node['windows']['Policy']['DeviceGuard'] do
  values [{
    name: 'LsaCfgFlags',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn On Virtualization Based Security - Select Platform Security Level

registry_key node['windows']['Policy']['DeviceGuard'] do
  values [{
    name: 'RequirePlatformSecurityFeatures',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow remote access to the Plug and Play interface

registry_key node['windows']['Policy']['AllowRemoteRPC'] do
  values [{
    name: 'AllowRemoteRPC',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Do not send a Windows error report when a generic driver is installed on a device

registry_key node['windows']['Policy']['DisableSendGenericDriverNotFoundToWER'] do
  values [{
    name: 'DisableSendGenericDriverNotFoundToWER',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prevent creation of a system restore point during device activity that would normally prompt creation of a restore point

registry_key node['windows']['Policy']['DisableSystemRestore'] do
  values [{
    name: 'DisableSystemRestore',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prevent device metadata retrieval from the Internet

registry_key node['windows']['Policy']['PreventDeviceMetadataFromNetwork'] do
  values [{
    name: 'PreventDeviceMetadataFromNetwork',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prevent Windows from sending an error report when a device driver requests additional software during installation

registry_key node['windows']['Policy']['DisableSendRequestAdditionalSoftwareToWER'] do
  values [{
    name: 'DisableSendRequestAdditionalSoftwareToWER',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off "Found New Hardware" balloons during device installation

registry_key node['windows']['Policy']['DisableBalloonTips'] do
  values [{
    name: 'DisableBalloonTips',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow administrators to override Device Installation Restriction policies

registry_key node['windows']['Policy']['AllowAdminInstall'] do
  values [{
    name: 'AllowAdminInstall',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Prevent installation of removable devices

registry_key node['windows']['Policy']['DenyRemovableDevices'] do
  values [{
    name: 'DenyRemovableDevices',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Apply policy to removable media

registry_key node['windows']['Policy']['ApplyToRemovableMedia'] do
  values [{
    name: 'ApplyToRemovableMedia',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow non-administrators to install drivers for these device setup classes

registry_key node['windows']['Policy']['AllowUserDeviceClasses'] do
  values [{
    name: 'AllowUserDeviceClasses',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off Windows Update device driver search prompt

registry_key node['windows']['Policy']['DontPromptForWindowsUpdate'] do
  values [{
    name: 'DontPromptForWindowsUpdate',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Boot-Start Driver Initialization Policy

registry_key node['windows']['Policy']['DriverLoadPolicy'] do
  values [{
    name: 'DriverLoadPolicy',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# File Classification Infrastructure: Display Classification tab in File Explorer

registry_key node['windows']['Policy']['EnableManualUX'] do
  values [{
    name: 'EnableManualUX',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow asynchronous user Group Policy processing when logging on through Remote Desktop Services

registry_key node['windows']['Policy']['ProcessTSUserLogonAsync'] do
  values [{
    name: 'ProcessTSUserLogonAsync',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Configure registry policy processing

registry_key node['windows']['Policy']['GP'] do
  values [
    { name: 'NoBackgroundPolicy', type: :dword, data: 0 },
    { name: 'NoGPOListChanges', type: :dword, data: 0 },
  ]
  recursive true
  action :create
end

# Configure scripts policy processing

registry_key node['windows']['Policy']['Script'] do
  values [
    { name: 'NoGPOListChanges', type: :dword, data: 0 },
  ]
  recursive true
  action :create
end

# Configure security policy processing

registry_key node['windows']['Policy']['Security'] do
  values [
    { name: 'NoGPOListChanges', type: :dword, data: 0 },
  ]
  recursive true
  action :create
end

# Continue experiences on this device

registry_key node['windows']['Policy']['EnableCdp'] do
  values [{
    name: 'EnableCdp',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off background refresh of Group Policy

registry_key node['windows']['Policy']['DisableBkGndGroupPolicy'] do
  values [{
    name: 'DisableBkGndGroupPolicy',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Restrict Internet communication

registry_key node['windows']['Policy']['RestrictCommunication'] do
  values [{
    name: 'RestrictCommunication',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off access to all Windows Update features

registry_key node['windows']['Policy']['DisableWindowsUpdateAccess'] do
  values [{
    name: 'DisableWindowsUpdateAccess',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off access to the Store

registry_key node['windows']['Policy']['NoUseStoreOpenWith'] do
  values [{
    name: 'NoUseStoreOpenWith',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off Automatic Root Certificates Update

registry_key node['windows']['Policy']['DisableRootAutoUpdate'] do
  values [{
    name: 'DisableRootAutoUpdate',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off downloading of print drivers over HTTP

registry_key node['windows']['Policy']['DisableWebPnPDownload'] do
  values [{
    name: 'DisableWebPnPDownload',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off handwriting personalization data sharing

registry_key node['windows']['Policy']['PreventHandwritingDataSharing'] do
  values [{
    name: 'PreventHandwritingDataSharing',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off handwriting recognition error reporting

registry_key node['windows']['Policy']['PreventHandwritingErrorReports'] do
  values [{
    name: 'PreventHandwritingErrorReports',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off Help and Support Center "Did you know?" content

registry_key node['windows']['Policy']['Headlines'] do
  values [{
    name: 'Headlines',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off Help and Support Center Microsoft Knowledge Base search

registry_key node['windows']['Policy']['MicrosoftKBSearch'] do
  values [{
    name: 'MicrosoftKBSearch',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com

registry_key node['windows']['Policy']['ExitOnMSICW'] do
  values [{
    name: 'ExitOnMSICW',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off Internet download for Web publishing and online ordering wizards

registry_key node['windows']['Policy']['NoWebServices'] do
  values [{
    name: 'NoWebServices',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off printing over HTTP

registry_key node['windows']['Policy']['DisableHTTPPrinting'] do
  values [{
    name: 'DisableHTTPPrinting',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off Registration if URL connection is referring to Microsoft.com

registry_key node['windows']['Policy']['NoRegistration'] do
  values [{
    name: 'NoRegistration',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off Search Companion content file updates

registry_key node['windows']['Policy']['DisableContentFileUpdates'] do
  values [{
    name: 'DisableContentFileUpdates',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off the "Order Prints" picture task

registry_key node['windows']['Policy']['NoOnlinePrintsWizard'] do
  values [{
    name: 'NoOnlinePrintsWizard',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off the "Publish to Web" task for files and folders

registry_key node['windows']['Policy']['NoPublishingWizard'] do
  values [{
    name: 'NoPublishingWizard',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off the Windows Messenger Customer Experience Improvement Program

registry_key node['windows']['Policy']['CEIP'] do
  values [{
    name: 'CEIP',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Turn off Windows Customer Experience Improvement Program

registry_key node['windows']['Policy']['CEIPEnable'] do
  values [{
    name: 'CEIPEnable',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off Windows Error Reporting

registry_key node['windows']['Policy']['ErrorReporting'] do
  values [{ name: 'DoReport', type: :dword, data: '0' }]
  action :create
  recursive true
end

registry_key node['windows']['Policy']['WindowsErrorReporting'] do
  values [{ name: 'Disabled', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Support device authentication using certificate

registry_key node['windows']['Policy']['Kerberos'] do
  values [
    { name: 'DevicePKInitBehavior', type: :dword, data: 0 },
    { name: 'DevicePKInitEnabled', type: :dword, data: 1 },
  ]
  recursive true
  action :create
end

# Enumeration policy for external devices incompatible with Kernel DMA Protection

registry_key node['windows']['Policy']['DeviceEnumerationPolicy'] do
  values [{
    name: 'DeviceEnumerationPolicy',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Disallow copying of user input methods to the system account for sign-in

registry_key node['windows']['Policy']['BlockUserInputMethodsForSignIn'] do
  values [{
    name: 'BlockUserInputMethodsForSignIn',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Block user from showing account details on sign-in

registry_key node['windows']['Policy']['BlockUserFromShowingAccountDetailsOnSignin'] do
  values [{
    name: 'BlockUserFromShowingAccountDetailsOnSignin',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Do not display network selection UI

registry_key node['windows']['Policy']['DontDisplayNetworkSelectionUI'] do
  values [{
    name: 'DontDisplayNetworkSelectionUI',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Do not enumerate connected users on domain-joined computers

registry_key node['windows']['Policy']['DontEnumerateConnectedUsers'] do
  values [{
    name: 'DontEnumerateConnectedUsers',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Enumerate local users on domain-joined computers

registry_key node['windows']['Policy']['EnumerateLocalUsers'] do
  values [{
    name: 'EnumerateLocalUsers',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off app notifications on the lock screen

registry_key node['windows']['Policy']['DisableLockScreenAppNotifications'] do
  values [{
    name: 'DisableLockScreenAppNotifications',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off picture password sign-in

registry_key node['windows']['Policy']['BlockDomainPicturePassword'] do
  values [{
    name: 'BlockDomainPicturePassword',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn on convenience PIN sign-in

registry_key node['windows']['Policy']['AllowDomainPINLogon'] do
  values [{
    name: 'AllowDomainPINLogon',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Untrusted Font Blocking

registry_key node['windows']['Policy']['MitigationOptions_FontBocking'] do
  values [{
    name: 'MitigationOptions_FontBocking',
    type: :string,
    data: '1000000000000',
  }]
  recursive true
  action :create
end

# Allow cryptography algorithms compatible with Windows NT 4.0

registry_key node['windows']['Policy']['AllowNT4Crypto'] do
  values [{
    name: 'AllowNT4Crypto',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Do not use NetBIOS-based discovery for domain controller location when DNS-based discovery fails

registry_key node['windows']['Policy']['AvoidFallbackNetbiosDiscovery'] do
  values [{
    name: 'AvoidFallbackNetbiosDiscovery',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow Clipboard History

registry_key node['windows']['Policy']['AllowClipboardHistory'] do
  values [{
    name: 'AllowClipboardHistory',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow Clipboard synchronization across devices

registry_key node['windows']['Policy']['AllowCrossDeviceClipboard'] do
  values [{
    name: 'AllowCrossDeviceClipboard',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow publishing of User Activities

registry_key node['windows']['Policy']['PublishUserActivities'] do
  values [{
    name: 'PublishUserActivities',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow upload of User Activities

registry_key node['windows']['Policy']['UploadUserActivities'] do
  values [{
    name: 'UploadUserActivities',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Enables Activity Feed

registry_key node['windows']['Policy']['EnableActivityFeed'] do
  values [{
    name: 'EnableActivityFeed',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow network connectivity during connected-standby (on battery)

registry_key node['windows']['Policy']['DCSettingIndex'] do
  values [{ name: 'DCSettingIndex', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Allow network connectivity during connected-standby (plugged in)

registry_key node['windows']['Policy']['ACSettingIndex'] do
  values [{ name: 'ACSettingIndex', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Require a password when a computer wakes (on battery) AND Require a password when a computer wakes (plugged in)

registry_key node['windows']['Policy']['Password']['Computer']['Wakes'] do
  values [
    { name: 'DCSettingIndex', type: :dword, data: 1 },
    { name: 'ACSettingIndex', type: :dword, data: 1 },
  ]
  recursive true
  action :create
end

# Configure Offer Remote Assistance

registry_key node['windows']['Policy']['fAllowUnsolicited'] do
  values [{
    name: 'fAllowUnsolicited',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Configure Solicited Remote Assistance

registry_key node['windows']['Policy']['fAllowToGetHelp'] do
  values [{
    name: 'fAllowToGetHelp',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Enable RPC Endpoint Mapper Client Authentication

registry_key node['windows']['Policy']['EnableAuthEpResolution'] do
  values [{ name: 'EnableAuthEpResolution', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Restrict Unauthenticated RPC clients

registry_key node['windows']['Policy']['RestrictRemoteClients'] do
  values [{ name: 'RestrictRemoteClients', type: :dword, data: 1 }]
  recursive true
  action :create
end

# Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider

registry_key node['windows']['Policy']['DisableQueryRemoteServer'] do
  values [{ name: 'DisableQueryRemoteServer', type: :dword, data: 0 }]
  recursive true
  action :create
end

# Troubleshooting: Allow users to access and run Troubleshooting Wizards

registry_key node['windows']['Policy']['EnableDiagnostics'] do
  values [{
    name: 'EnableDiagnostics',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Troubleshooting: Allow users to access online troubleshooting content on Microsoft servers from the Troubleshooting Control Panel (via the Windows Online Troubleshooting Service - WOTS)

registry_key node['windows']['Policy']['EnableQueryRemoteServer'] do
  values [{
    name: 'EnableQueryRemoteServer',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Enable/Disable PerfTrack

registry_key node['windows']['Policy']['ScenarioExecutionEnabled'] do
  values [{ name: 'ScenarioExecutionEnabled', type: :dword, data: 0 }]
  action :create
  recursive true
end

# Turn off the advertising ID

registry_key node['windows']['Policy']['DisabledByGroupPolicy'] do
  values [{
    name: 'DisabledByGroupPolicy',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Hide the file scan progress window

registry_key node['windows']['Policy']['SfcShowProgress'] do
  values [{
    name: 'SfcShowProgress',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Enable Windows NTP Client

registry_key node['windows']['Policy']['NtpClient'] do
  values [{ name: 'Enabled', type: :dword, data: 1 }]
  recursive true
  action :create
end

# Enable Windows NTP Server

registry_key node['windows']['Policy']['NtpServer'] do
  values [{ name: 'Enabled', type: :dword, data: 0 }]
  recursive true
  action :create
end

# Approved Installation Sites for ActiveX Controls

registry_key node['windows']['Policy']['ApprovedList'] do
  values [{
    name: 'ApprovedList',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Establish ActiveX installation policy for sites in Trusted zones

registry_key node['windows']['Policy']['AxISURLZonePolicies'] do
  values [{
    name: 'InstallTrustedOCX',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['AxISURLZonePolicies'] do
  values [{
    name: 'InstallSignedOCX',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['AxISURLZonePolicies'] do
  values [{
    name: 'InstallUnSignedOCX',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow a Windows app to share application data between users

registry_key node['windows']['Policy']['AllowSharedLocalAppData'] do
  values [{ name: 'AllowSharedLocalAppData', type: :dword, data: 0 }]
  recursive true
  action :create
end

# Allow all trusted apps to install

registry_key node['windows']['Policy']['AllowAllTrustedApps'] do
  values [{
    name: 'AllowAllTrustedApps',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow deployment operations in special profiles

registry_key node['windows']['Policy']['AllowDeploymentInSpecialProfiles'] do
  values [{
    name: 'AllowDeploymentInSpecialProfiles',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allows development of Windows Store apps and installing them from an integrated development environment (IDE)

registry_key node['windows']['Policy']['AllowDevelopmentWithoutDevLicense'] do
  values [{
    name: 'AllowDevelopmentWithoutDevLicense',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Prevent users' app data from being stored on non-system volumes

registry_key node['windows']['Policy']['RestrictAppDataToSystemVolume'] do
  values [{
    name: 'RestrictAppDataToSystemVolume',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Let Windows apps access account information

registry_key node['windows']['Policy']['LetAppsAccessAccountInfo'] do
  values [{
    name: 'LetAppsAccessAccountInfo',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps access an eye tracker device

registry_key node['windows']['Policy']['LetAppsAccessGazeInput'] do
  values [{
    name: 'LetAppsAccessGazeInput',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps access call history

registry_key node['windows']['Policy']['LetAppsAccessCallHistory'] do
  values [{
    name: 'LetAppsAccessCallHistory',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps access contacts

registry_key node['windows']['Policy']['LetAppsAccessContacts'] do
  values [{
    name: 'LetAppsAccessContacts',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps access diagnostic information about other apps

registry_key node['windows']['Policy']['LetAppsGetDiagnosticInfo'] do
  values [{
    name: 'LetAppsGetDiagnosticInfo',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps access email

registry_key node['windows']['Policy']['LetAppsAccessEmail'] do
  values [{
    name: 'LetAppsAccessEmail',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps access location

registry_key node['windows']['Policy']['LetAppsAccessLocation'] do
  values [{
    name: 'LetAppsAccessLocation',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps access messaging

registry_key node['windows']['Policy']['LetAppsAccessMessaging'] do
  values [{
    name: 'LetAppsAccessMessaging',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps access motion

registry_key node['windows']['Policy']['LetAppsAccessMotion'] do
  values [{
    name: 'LetAppsAccessMotion',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps access notifications

registry_key node['windows']['Policy']['LetAppsAccessNotifications'] do
  values [{
    name: 'LetAppsAccessNotifications',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps access Tasks

registry_key node['windows']['Policy']['LetAppsAccessTasks'] do
  values [{
    name: 'LetAppsAccessTasks',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps access the calendar

registry_key node['windows']['Policy']['LetAppsAccessCalendar'] do
  values [{
    name: 'LetAppsAccessCalendar',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps access the camera

registry_key node['windows']['Policy']['LetAppsAccessCamera'] do
  values [{
    name: 'LetAppsAccessCamera',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps access the microphone

registry_key node['windows']['Policy']['LetAppsAccessMicrophone'] do
  values [{
    name: 'LetAppsAccessMicrophone',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps access trusted devices

registry_key node['windows']['Policy']['LetAppsAccessTrustedDevices'] do
  values [{
    name: 'LetAppsAccessTrustedDevices',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps communicate with unpaired devices

registry_key node['windows']['Policy']['LetAppsSyncWithDevices'] do
  values [{
    name: 'LetAppsSyncWithDevices',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps control radios

registry_key node['windows']['Policy']['LetAppsAccessRadios'] do
  values [{
    name: 'LetAppsAccessRadios',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps make phone calls

registry_key node['windows']['Policy']['LetAppsAccessPhone'] do
  values [{
    name: 'LetAppsAccessPhone',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Let Windows apps run in the background

registry_key node['windows']['Policy']['LetAppsRunInBackground'] do
  values [{
    name: 'LetAppsRunInBackground',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Allow Microsoft accounts to be optional

registry_key node['windows']['Policy']['MSAOptional'] do
  values [{
    name: 'MSAOptional',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Block launching Universal Windows apps with Windows Runtime API access from hosted content.

registry_key node['windows']['Policy']['BlockHostedAppAccessWinRT'] do
  values [{
    name: 'BlockHostedAppAccessWinRT',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prevent access to 16-bit applications

registry_key node['windows']['Policy']['VDMDisallowed'] do
  values [{
    name: 'VDMDisallowed',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Remove Program Compatibility Property Page

registry_key node['windows']['Policy']['DisablePropPage'] do
  values [{
    name: 'DisablePropPage',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off Application Compatibility Engine

registry_key node['windows']['Policy']['DisableEngine'] do
  values [{
    name: 'DisableEngine',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off Application Telemetry

registry_key node['windows']['Policy']['AITEnable'] do
  values [{
    name: 'AITEnable',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off Inventory Collector

registry_key node['windows']['Policy']['DisableInventory'] do
  values [{
    name: 'DisableInventory',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off Program Compatibility Assistant

registry_key node['windows']['Policy']['DisablePCA'] do
  values [{
    name: 'DisablePCA',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off Steps Recorder

registry_key node['windows']['Policy']['DisableUAR'] do
  values [{
    name: 'DisableUAR',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off SwitchBack Compatibility Engine

registry_key node['windows']['Policy']['SbEnable'] do
  values [{
    name: 'SbEnable',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Disallow Autoplay for non-volume devices

registry_key node['windows']['Policy']['NoAutoplayfornonVolume'] do
  values [{
    name: 'NoAutoplayfornonVolume',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prevent AutoPlay from remembering user choices.

registry_key node['windows']['Policy']['DontSetAutoplayCheckbox'] do
  values [{
    name: 'DontSetAutoplayCheckbox',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Set the default behavior for AutoRun

registry_key node['windows']['Policy']['NoAutorun'] do
  values [{
    name: 'NoAutorun',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off Autoplay

registry_key node['windows']['Policy']['NoDriveTypeAutoRun'] do
  values [{
    name: 'NoDriveTypeAutoRun',
    type: :dword,
    data: 255,
  }]
  recursive true
  action :create
end

# Allow the use of biometrics

registry_key node['windows']['Policy']['Biometrics'] do
  values [{
    name: 'Enabled',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow users to log on using biometrics

registry_key node['windows']['Policy']['Credential'] do
  values [{
    name: 'Enabled',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Configure enhanced anti-spoofing

registry_key node['windows']['Policy']['EnhancedAntiSpoofing'] do
  values [{
    name: 'EnhancedAntiSpoofing',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow Use of Camera

registry_key node['windows']['Policy']['AllowCamera'] do
  values [{
    name: 'AllowCamera',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Do not show Windows tips

registry_key node['windows']['Policy']['DisableSoftLanding'] do
  values [{
    name: 'DisableSoftLanding',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off Microsoft consumer experiences

registry_key node['windows']['Policy']['DisableWindowsConsumerFeatures'] do
  values [{
    name: 'DisableWindowsConsumerFeatures',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Require pin for pairing

registry_key node['windows']['Policy']['RequirePinForPairing'] do
  values [{
    name: 'RequirePinForPairing',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Do not display the password reveal button

registry_key node['windows']['Policy']['DisablePasswordReveal'] do
  values [{
    name: 'DisablePasswordReveal',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Enumerate administrator accounts on elevation

registry_key node['windows']['Policy']['EnumerateAdministrators'] do
  values [{
    name: 'EnumerateAdministrators',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow device name to be sent in Windows diagnostic data

registry_key node['windows']['Policy']['AllowDeviceNameInTelemetry'] do
  values [{
    name: 'AllowDeviceNameInTelemetry',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow Telemetry

registry_key node['windows']['Policy']['AllowTelemetry'] do
  values [{
    name: 'AllowTelemetry',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service

registry_key node['windows']['Policy']['DisableEnterpriseAuthProxy'] do
  values [{
    name: 'DisableEnterpriseAuthProxy',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Configure Connected User Experiences and Telemetry

registry_key node['windows']['Policy']['TelemetryProxyServer'] do
  values [{
    name: 'TelemetryProxyServer',
    type: :string,
    data: '',
  }]
  recursive true
  action :create
end

# Do not show feedback notifications

registry_key node['windows']['Policy']['DoNotShowFeedbackNotifications'] do
  values [{
    name: 'DoNotShowFeedbackNotifications',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Toggle user control over Insider builds

registry_key node['windows']['Policy']['AllowBuildPreview'] do
  values [{
    name: 'AllowBuildPreview',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Do not allow Digital Locker to run

registry_key node['windows']['Policy']['DoNotRunDigitalLocker'] do
  values [{
    name: 'DoNotRunDigitalLocker',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Back up log automatically when full

registry_key node['windows']['Policy']['AutoBackupLogFiles'] do
  values [{
    name: 'AutoBackupLogFiles',
    type: :string,
    data: 1,
  }]
  recursive true
  action :create
end

# Control Event Log behavior when the log file reaches its maximum size

registry_key node['windows']['Policy']['Application']['Retention'] do
  values [{
    name: 'Retention',
    type: :string,
    data: 0,
  }]
  recursive true
  action :create
end

# Specify the maximum log file size (KB)

registry_key node['windows']['Policy']['Application']['MaxSize'] do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 32768,
  }]
  recursive true
  action :create
end

# Control Event Log behavior when the log file reaches its maximum size AND Specify the maximum log file size (KB)

registry_key node['windows']['Policy']['EventLogSecurity'] do
  values [
    { name: 'Retention', type: :string, data: 0 },
    { name: 'MaxSize', type: :dword, data: 196608 },
  ]
  recursive true
  action :create
end

# Back up log automatically when full

registry_key node['windows']['Policy']['Setup']['AutoBackupLogFiles'] do
  values [{
    name: 'AutoBackupLogFiles',
    type: :string,
    data: 1,
  }]
  recursive true
  action :create
end

# Control Event Log behavior when the log file reaches its maximum size

registry_key node['windows']['Policy']['Setup']['Retention'] do
  values [{
    name: 'Retention',
    type: :string,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on logging

registry_key node['windows']['Policy']['Logging'] do
  values [{
    name: 'Enabled',
    type: :string,
    data: 1,
  }]
  recursive true
  action :create
end

# Back up log automatically when full

registry_key node['windows']['Policy']['System']['AutoBackupLogFiles'] do
  values [{
    name: 'AutoBackupLogFiles',
    type: :string,
    data: 1,
  }]
  recursive true
  action :create
end

# Control Event Log behavior when the log file reaches its maximum size AND Specify the maximum log file size (KB)

registry_key node['windows']['Policy']['EventLogSystem'] do
  values [
    { name: 'Retention', type: :string, data: 0 },
    { name: 'MaxSize', type: :dword, data: 32768 },
  ]
  recursive true
  action :create
end

# Allow the use of remote paths in file shortcut icons

registry_key node['windows']['Policy']['EnableShellShortcutIconRemotePath'] do
  values [{
    name: 'EnableShellShortcutIconRemotePath',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Configure Windows Defender SmartScreen

registry_key node['windows']['Policy']['EnableSmartScreen'] do
  values [{
    name: 'EnableSmartScreen',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['EnableSmartScreen'] do
  values [{
    name: 'ShellSmartScreenLevel',
    type: :string,
    data: 'Block',
  }]
  recursive true
  action :create
end

# Turn off Data Execution Prevention for Explorer

registry_key node['windows']['Policy']['DataExecution'] do
  values [{
    name: 'NoDataExecutionPrevention',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off heap termination on corruption

registry_key node['windows']['Policy']['DataExecution'] do
  values [{
    name: 'NoHeapTerminationOnCorruption',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off shell protocol protected mode

registry_key node['windows']['Policy']['PreXPSP2ShellProtocolBehavior'] do
  values [{
    name: 'PreXPSP2ShellProtocolBehavior',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Prevent the computer from joining a homegroup

registry_key node['windows']['Policy']['DisableHomeGroup'] do
  values [{
    name: 'DisableHomeGroup',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prevent bypassing SmartScreen Filter warnings

registry_key node['windows']['Policy']['PhishingFilter'] do
  values [
    { name: 'PreventOverrideAppRepUnknown', type: :dword, data: 1 },
    { name: 'PreventOverride', type: :dword, data: 1 },
  ]
  recursive true
  action :create
end

# Prevent managing SmartScreen Filter

registry_key node['windows']['Policy']['PhishingFilter'] do
  values [{
    name: 'EnabledV9',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prevent per-user installation of ActiveX controls

registry_key node['windows']['Policy']['BlockNonAdminActiveXInstall'] do
  values [{
    name: 'BlockNonAdminActiveXInstall',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Security Zones: Do not allow users to add/delete sites

registry_key node['windows']['Policy']['SecurityZonesMapEdit'] do
  values [{
    name: 'Security_zones_map_edit',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Security Zones: Do not allow users to change policies

registry_key node['windows']['Policy']['SecurityOptionsEdit'] do
  values [{
    name: 'Security_options_edit',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Security Zones: Use only machine settings

registry_key node['windows']['Policy']['SecurityHKLM'] do
  values [{
    name: 'Security_HKLM_only',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Specify use of ActiveX Installer Service for installation of ActiveX controls

registry_key node['windows']['Policy']['OnlyUseAXISForActiveXInstall'] do
  values [{
    name: 'OnlyUseAXISForActiveXInstall',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off Crash Detection

registry_key node['windows']['Policy']['NoCrashDetection'] do
  values [{
    name: 'NoCrashDetection',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off the Security Settings Check feature

registry_key node['windows']['Policy']['DisableSecuritySettingsCheck'] do
  values [{
    name: 'DisableSecuritySettingsCheck',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Prevent ignoring certificate errors

registry_key node['windows']['Policy']['PreventIgnoreCertErrors'] do
  values [{
    name: 'PreventIgnoreCertErrors',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow software to run or install even if the signature is invalid

registry_key node['windows']['Policy']['RunInvalidSignatures'] do
  values [{
    name: 'RunInvalidSignatures',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Check for server certificate revocation

registry_key node['windows']['Policy']['CertificateRevocation'] do
  values [{
    name: 'CertificateRevocation',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Check for signatures on downloaded programs

registry_key node['windows']['Policy']['CheckExeSignatures'] do
  values [{
    name: 'CheckExeSignatures',
    type: :string,
    data: 'yes',
  }]
  recursive true
  action :create
end

# Do not allow ActiveX controls to run in Protected Mode when Enhanced Protected Mode is enabled

registry_key node['windows']['Policy']['DisableEPMCompat'] do
  values [{
    name: 'DisableEPMCompat',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off encryption support

registry_key node['windows']['Policy']['SecureProtocols'] do
  values [{
    name: 'SecureProtocols',
    type: :dword,
    data: 2048,
  }]
  recursive true
  action :create
end

# Turn on 64-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows

registry_key node['windows']['Policy']['Isolation64Bit'] do
  values [{
    name: 'Isolation64Bit',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn on Enhanced Protected Mode

registry_key node['windows']['Policy']['Isolation'] do
  values [{
    name: 'Isolation',
    type: :string,
    data: 'PMEM',
  }]
  recursive true
  action :create
end

# Intranet Sites: Include all network paths (UNCs)

registry_key node['windows']['Policy']['UNCAsIntranet'] do
  values [{
    name: 'UNCAsIntranet',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on certificate address mismatch warning

registry_key node['windows']['Policy']['WarnOnBadCertRecving'] do
  values [{
    name: 'WarnOnBadCertRecving',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Access data sources across domains

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '1406',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow cut, copy or paste operations from the clipboard via script

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '1407',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow drag and drop or copy and paste files

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '1802',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow loading of XAML files

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '2402',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow only approved domains to use ActiveX controls without prompt

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '120b',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow only approved domains to use the TDC ActiveX control

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '120c',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow scripting of Internet Explorer WebBrowser controls

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '1206',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow script-initiated windows without size or position constraints

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '2102',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow scriptlets

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '1209',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow updates to status bar via script

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '2103',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow VBScript to run in Internet Explorer

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '140C',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Automatic prompting for file downloads

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '2200',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Don't run antimalware programs against ActiveX controls

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '270C',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Download signed ActiveX controls

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '1001',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Download unsigned ActiveX controls

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '1004',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Enable dragging of content from different domains across windows

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '2709',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Enable dragging of content from different domains within a window

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '2708',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Include local path when user is uploading files to a server

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '160A',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Initialize and script ActiveX controls not marked as safe

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '1201',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Java permissions

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '1C00',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Launching applications and files in an IFRAME

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '1804',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Logon options

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '1A00',
    type: :dword,
    data: 65536,
  }]
  recursive true
  action :create
end

# Navigate windows and frames across different domains

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '1607',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Run .NET Framework-reliant components not signed with Authenticode

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '2004',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Run .NET Framework-reliant components signed with Authenticode

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '2001',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Show security warning for potentially unsafe files

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '1806',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn on Cross-Site Scripting Filter

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '1409',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on Protected Mode

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '2500',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on SmartScreen Filter scan

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '2301',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Use Pop-up Blocker

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '1809',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Userdata persistence

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '1606',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Web sites in less privileged Web content zones can navigate into this zone

registry_key node['windows']['Policy']['DataSources'] do
  values [{
    name: '2101',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Don't run antimalware programs against ActiveX controls

registry_key node['windows']['Policy']['IntranetDataSources'] do
  values [{
    name: '270C',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Initialize and script ActiveX controls not marked as safe

registry_key node['windows']['Policy']['IntranetDataSources'] do
  values [{
    name: '1201',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Java permissions

registry_key node['windows']['Policy']['IntranetDataSources'] do
  values [{
    name: '1C00',
    type: :dword,
    data: 65536,
  }]
  recursive true
  action :create
end

# Don't run antimalware programs against ActiveX controls

registry_key node['windows']['Policy']['LocalMahineZone'] do
  values [{
    name: '270C',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Java permissions

registry_key node['windows']['Policy']['LocalMahineZone'] do
  values [{
    name: '270C',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on SmartScreen Filter scan

registry_key node['windows']['Policy']['LockedDownInternet'] do
  values [{
    name: '2301',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Java permissions

registry_key node['windows']['Policy']['LockedDownIntranet'] do
  values [{
    name: '1C00',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Java permissions

registry_key node['windows']['Policy']['LockedLocalMahineZone'] do
  values [{
    name: '1C00',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Java permissions

registry_key node['windows']['Policy']['LockedRestrictedSiteZone'] do
  values [{
    name: '1C00',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on SmartScreen Filter scan

registry_key node['windows']['Policy']['LockedRestrictedSiteZone'] do
  values [{
    name: '2301',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Java permissions

registry_key node['windows']['Policy']['LockedTrustedSiteZone'] do
  values [{
    name: '1C00',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Access data sources across domains

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1406',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow active scripting

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1400',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow binary and script behaviors

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '2000',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow cut, copy or paste operations from the clipboard via script

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1407',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow drag and drop or copy and paste files

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1802',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow file downloads

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1803',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow loading of XAML files

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '2402',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow META REFRESH

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1608',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow only approved domains to use ActiveX controls without prompt

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '120b',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow only approved domains to use the TDC ActiveX control

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '120c',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow scripting of Internet Explorer WebBrowser controls

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1206',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow script-initiated windows without size or position constraints

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '2102',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow scriptlets

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1209',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow updates to status bar via script

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '2103',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Allow VBScript to run in Internet Explorer

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '140C',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Automatic prompting for file downloads

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '2200',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Don't run antimalware programs against ActiveX controls

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '270C',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Download signed ActiveX controls

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1001',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Download unsigned ActiveX controls

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1004',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Enable dragging of content from different domains across windows

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '2709',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Enable dragging of content from different domains within a window

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '2708',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Include local path when user is uploading files to a server

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '160A',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Initialize and script ActiveX controls not marked as safe

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1201',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Java permissions

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1C00',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Launching applications and files in an IFRAME

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1804',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Logon options

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1A00',
    type: :dword,
    data: 196608,
  }]
  recursive true
  action :create
end

# Navigate windows and frames across different domains

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1607',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Run .NET Framework-reliant components not signed with Authenticode

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '2004',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Run .NET Framework-reliant components signed with Authenticode

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '2001',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Run ActiveX controls and plugins

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1200',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Script ActiveX controls marked safe for scripting

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1405',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Scripting of Java applets

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1402',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Show security warning for potentially unsafe files

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1806',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Turn on Cross-Site Scripting Filter

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1409',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on Protected Mode

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '2500',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on SmartScreen Filter scan

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '2301',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Use Pop-up Blocker

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1809',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Userdata persistence

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '1606',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Web sites in less privileged Web content zones can navigate into this zone

registry_key node['windows']['Policy']['RestrictedSiteZone'] do
  values [{
    name: '2101',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Don't run antimalware programs against ActiveX controls

registry_key node['windows']['Policy']['TrustedSiteZone'] do
  values [{
    name: '270C',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Initialize and script ActiveX controls not marked as safe

registry_key node['windows']['Policy']['TrustedSiteZone'] do
  values [{
    name: '1201',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Java permissions

registry_key node['windows']['Policy']['TrustedSiteZone'] do
  values [{
    name: '1C00',
    type: :dword,
    data: 65536,
  }]
  recursive true
  action :create
end

# Allow fallback to SSL 3.0 (Internet Explorer)

registry_key node['windows']['Policy']['EnableSSL3Fallback'] do
  values [{
    name: 'EnableSSL3Fallback',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Remove "Run this time" button for outdated ActiveX controls in Internet Explorer

registry_key node['windows']['Policy']['RunThisTimeEnabled'] do
  values [{
    name: 'RunThisTimeEnabled',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off blocking of outdated ActiveX controls for Internet Explorer

registry_key node['windows']['Policy']['VersionCheckEnabled'] do
  values [{
    name: 'VersionCheckEnabled',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Windows Components\Internet Explorer\Security Features\Consistent Mime Handling - Internet Explorer Processes

registry_key node['windows']['Policy']['InternetExplorerConsistent'] do
  values [{
    name: 'Reserved',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['InternetExplorerConsistent'] do
  values [{
    name: 'explorer.exe',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['InternetExplorerConsistent'] do
  values [{
    name: 'iexplore.exe',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

# Windows Components\Internet Explorer\Security Features\Mime Sniffing Safety Feature - Internet Explorer Processes

registry_key node['windows']['Policy']['InternetExplorerSniffing'] do
  values [{
    name: 'Reserved',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['InternetExplorerSniffing'] do
  values [{
    name: 'explorer.exe',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['InternetExplorerSniffing'] do
  values [{
    name: 'iexplore.exe',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

# Windows Components\Internet Explorer\Security Features\MK Protocol Security Restriction - Internet Explorer Processes

registry_key node['windows']['Policy']['InternetExplorerMKProtocol'] do
  values [{
    name: 'Reserved',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['InternetExplorerMKProtocol'] do
  values [{
    name: 'explorer.exe',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['InternetExplorerMKProtocol'] do
  values [{
    name: 'iexplore.exe',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

# Windows Components\Internet Explorer\Security Features\Notification bar - Internet Explorer Processes

registry_key node['windows']['Policy']['InternetExplorerNotificationBar'] do
  values [{
    name: 'Reserved',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['InternetExplorerNotificationBar'] do
  values [{
    name: 'explorer.exe',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['InternetExplorerNotificationBar'] do
  values [{
    name: 'iexplore.exe',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

# Windows Components\Internet Explorer\Security Features\Protection From Zone Elevation - Internet Explorer Processes

registry_key node['windows']['Policy']['InternetExplorerZoneElevation'] do
  values [{
    name: 'Reserved',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['InternetExplorerZoneElevation'] do
  values [{
    name: 'explorer.exe',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['InternetExplorerZoneElevation'] do
  values [{
    name: 'iexplore.exe',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

# Windows Components\Internet Explorer\Security Features\Restrict ActiveX Install - Internet Explorer Processes

registry_key node['windows']['Policy']['InternetExplorerRestrictActiveX'] do
  values [{
    name: 'Reserved',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['InternetExplorerRestrictActiveX'] do
  values [{
    name: 'explorer.exe',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['InternetExplorerRestrictActiveX'] do
  values [{
    name: 'iexplore.exe',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

# Windows Components\Internet Explorer\Security Features\Restrict File Download - Internet Explorer Processes

registry_key node['windows']['Policy']['InternetExplorerRestrictDownload'] do
  values [{
    name: 'Reserved',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['InternetExplorerRestrictDownload'] do
  values [{
    name: 'explorer.exe',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['InternetExplorerRestrictDownload'] do
  values [{
    name: 'iexplore.exe',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

# Windows Components\Internet Explorer\Security Features\Scripted Window Security Restrictions - Internet Explorer Processes

registry_key node['windows']['Policy']['InternetExplorerWindowRestriction'] do
  values [{
    name: 'Reserved',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['InternetExplorerWindowRestriction'] do
  values [{
    name: 'explorer.exe',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['InternetExplorerWindowRestriction'] do
  values [{
    name: 'iexplore.exe',
    type: :string,
    data: '1',
  }]
  recursive true
  action :create
end

# Turn off location

registry_key node['windows']['Policy']['DisableLocation'] do
  values [{ name: 'DisableLocation', type: :dword, data: 1 }]
  recursive true
  action :create
end

# Turn off location scripting

registry_key node['windows']['Policy']['DisableLocationScripting'] do
  values [{
    name: 'DisableLocationScripting',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off sensors

registry_key node['windows']['Policy']['DisableSensors'] do
  values [{
    name: 'DisableSensors',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off Windows Location Provider

registry_key node['windows']['Policy']['DisableWindowsLocationProvider'] do
  values [{
    name: 'DisableWindowsLocationProvider',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Automatic Maintenance WakeUp Policy

registry_key node['windows']['Policy']['WakeUp'] do
  values [{
    name: 'WakeUp',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off Automatic Download and Update of Map Data

registry_key node['windows']['Policy']['AutoDownloadAndUpdateMapData'] do
  values [{
    name: 'AutoDownloadAndUpdateMapData',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off unsolicited network traffic on the Offline Maps settings page

registry_key node['windows']['Policy']['AllowUntriggeredNetworkTrafficOnSettingsPage'] do
  values [{
    name: 'AllowUntriggeredNetworkTrafficOnSettingsPage',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow Message Service Cloud Sync

registry_key node['windows']['Policy']['AllowMessageSync'] do
  values [{
    name: 'AllowMessageSync',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Block all consumer Microsoft account user authentication

registry_key node['windows']['Policy']['DisableUserAuth'] do
  values [{
    name: 'DisableUserAuth',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Disable remote Desktop Sharing

registry_key node['windows']['Policy']['NoRDS'] do
  values [{
    name: 'NoRDS',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prevent the usage of OneDrive for file storage

registry_key node['windows']['Policy']['OneDrive'] do
  values [{ name: 'DisableFileSyncNGSC', type: :dword, data: 1 }]
  recursive true
  action :create
end

# Save documents to OneDrive by default

registry_key node['windows']['Policy']['OneDrive'] do
  values [{ name: 'DisableLibrariesDefaultSaveToOneDrive', type: :dword, data: 0 }]
  recursive true
  action :create
end

# Allow .rdp files from unknown publishers

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'AllowUnsignedFiles',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow .rdp files from valid publishers and user's default .rdp settings

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'AllowSignedFiles',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Configure server authentication for client

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'AuthenticationLevel',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Do not allow hardware accelerated decoding

registry_key node['windows']['Policy']['EnableHardwareMode'] do
  values [{
    name: 'EnableHardwareMode',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Do not allow passwords to be saved

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'DisablePasswordSaving',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prompt for credentials on the client computer

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'PromptForCredsOnClient',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Specify SHA1 thumbprints of certificates representing trusted .rdp publishers

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'TrustedCertThumbprints',
    type: :string,
    data: 'Disabled',
  }]
  recursive true
  action :create
end

# Turn Off UDP On Client

registry_key node['windows']['Policy']['fClientDisableUDP'] do
  values [{
    name: 'fClientDisableUDP',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow RDP redirection of other supported RemoteFX USB devices from this computer

registry_key node['windows']['Policy']['fUsbRedirectionEnableMode'] do
  values [{
    name: 'fUsbRedirectionEnableMode',
    type: :dword,
    data: '',
    }]
  action :delete
end

# Turn off Windows Installer RDS Compatibility

registry_key node['windows']['Policy']['RDSCompatibility'] do
  values [{
    name: 'Enable',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow remote start of unlisted programs

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fAllowUnlistedRemotePrograms',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow users to connect remotely by using Remote Desktop Services

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fDenyTSConnection',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Automatic reconnection

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fDisableAutoReconnect',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Configure keep-alive connection interval

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'KeepAliveEnable',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'KeepAliveInterval',
    type: :dword,
    data: 120,
  }]
  recursive true
  action :create
end

# Limit number of connections

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'MaxInstanceCount',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Restrict Remote Desktop Services users to a single Remote Desktop Services session

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fSingleSessionPerUser',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Select RDP transport protocols

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'SelectTransport',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow audio and video playback redirection

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fDisableCam',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow audio recording redirection

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fDisableAudioCapture',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow time zone redirection

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fEnableTimeZoneRedirection',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Do not allow Clipboard redirection

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fDisableClip',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Do not allow COM port redirection

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fDisableCcm',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Do not allow drive redirection

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fDisableCdm',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Do not allow LPT port redirection

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fDisableLPT',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Do not allow smart card device redirection

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fEnableSmartCard',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Do not allow supported Plug and Play device redirection

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fDisablePNPRedir',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Do not allow video capture redirection

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fDisableCameraRedir',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Limit audio playback quality

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'AllowedAudioQualityMode',
    type: :dword,
    data: '',
    }]
  action :delete
end

# Hide notifications about RD Licensing problems that affect the RD Session Host server

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fDisableTerminalServerTooltip',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Do not allow client printer redirection

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fDisableCpm',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Do not set default client printer to be default printer in a session

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fForceClientLptDef',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Redirect only the default client printer

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'RedirectOnlyDefaultClientPrinter',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Specify RD Session Host server fallback printer driver behavior

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fPolicyFallbackPrintDriver',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Use Remote Desktop Easy Print printer driver first

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'UseUniversalPrinterDriverFirst',
    type: :dword,
    data: 4,
  }]
  recursive true
  action :create
end

# Allow desktop composition for remote desktop sessions

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fAllowDesktopCompositionOnServer',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Do not allow font smoothing

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fNoFontSmoothing',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Limit number of monitors

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'MaxMonitors',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Remove Windows Security item from Start menu

registry_key node['windows']['Policy']['NoNTSecurity'] do
  values [{
    name: 'NoNTSecurity',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Always prompt for password upon connection

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fPromptForPassword',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Do not allow local administrators to customize permissions

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fWritableTSCCPermTab',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Require secure RPC communication

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'fEncryptRPCTraffic',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Require use of specific security layer for remote (RDP) connections

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'SecurityLayer',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Require user authentication for remote connections by using Network Level Authentication

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'UserAuthentication',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Server authentication certificate template

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'CertTemplateName',
    type: :string,
    data: 'RemoteDesktopComputer',
  }]
  recursive true
  action :create
end

# Set client connection encryption level

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'MinEncryptionLevel',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Set time limit for active but idle Remote Desktop Services sessions

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'MaxIdleTime',
    type: :dword,
    data: 900000,
  }]
  recursive true
  action :create
end

# Set time limit for disconnected sessions

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'MaxDisconnectionTime',
    type: :dword,
    data: 7200000,
  }]
  recursive true
  action :create
end

# Set time limit for logoff of RemoteApp sessions

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'RemoteAppLogoffTimeLimit',
    type: :dword,
    data: 7200000,
  }]
  recursive true
  action :create
end

# Do not delete temp folders upon exit

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'DeleteTempDirsOnExit',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Do not use temporary folders per session

registry_key node['windows']['Policy']['Terminal'] do
  values [{
    name: 'PerSessionTempDir',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Prevent downloading of enclosures

registry_key node['windows']['Policy']['DisableEnclosureDownload'] do
  values [{
    name: 'DisableEnclosureDownload',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow Cloud Search

registry_key node['windows']['Policy']['AllowCloudSearch'] do
  values [{
    name: 'AllowCloudSearch',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow Cortana

registry_key node['windows']['Policy']['Cortana'] do
  values [{
    name: 'AllowCortana',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow Cortana above lock screen

registry_key node['windows']['Policy']['Cortana'] do
  values [{
    name: 'AllowCortanaAboveLock',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow Cortana Page in OOBE on an AAD account

registry_key node['windows']['Policy']['Cortana'] do
  values [{
    name: 'AllowCortanaInAADPathOOBE',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow indexing of encrypted files

registry_key node['windows']['Policy']['Cortana'] do
  values [{
    name: 'AllowIndexingEncryptedStoresOrItems',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow search and Cortana to use location

registry_key node['windows']['Policy']['Cortana'] do
  values [{
    name: 'AllowSearchToUseLocation',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow use of diacritics

registry_key node['windows']['Policy']['Cortana'] do
  values [{
    name: 'AllowUsingDiacritics',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off KMS Client Online AVS Validation

registry_key node['windows']['Policy']['NoGenTicket'] do
  values [{
    name: 'NoGenTicket',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Disable all apps from Microsoft Store

registry_key node['windows']['Policy']['DisableStoreApps'] do
  values [{
    name: 'DisableStoreApps',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Only display the private store within the Microsoft Store

registry_key node['windows']['Policy']['RequirePrivateStoreOnly'] do
  values [{
    name: 'RequirePrivateStoreOnly',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off Automatic Download and Install of updates

registry_key node['windows']['Policy']['AutoDownload'] do
  values [{
    name: 'AutoDownload',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Turn off Automatic Download of updates on Win8 machines

registry_key node['windows']['Policy']['AutoDownload'] do
  values [{
    name: 'AutoDownload',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Turn off the offer to update to the latest version of Windows

registry_key node['windows']['Policy']['DisableOSUpgrade'] do
  values [{
    name: 'DisableOSUpgrade',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off the Store application

registry_key node['windows']['Policy']['RemoveWindowsStore'] do
  values [{
    name: 'RemoveWindowsStore',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Hide Advanced Properties Checkbox in Add Scheduled Task Wizard

registry_key node['windows']['Policy']['Scheduler'] do
  values [{
    name: 'Disable Advanced',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Hide Property Pages

registry_key node['windows']['Policy']['Scheduler'] do
  values [{
    name: 'Property Pages',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prevent Task Run or End

registry_key node['windows']['Policy']['Scheduler'] do
  values [{
    name: 'Execution',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prohibit Browse

registry_key node['windows']['Policy']['Scheduler'] do
  values [{
    name: 'Allow Browse',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prohibit Drag-and-Drop

registry_key node['windows']['Policy']['Scheduler'] do
  values [{
    name: 'DragAndDrop',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prohibit New Task Creation

registry_key node['windows']['Policy']['Scheduler'] do
  values [{
    name: 'Task Creation',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Prohibit Task Deletion

registry_key node['windows']['Policy']['Scheduler'] do
  values [{
    name: 'Task Deletion',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow Uninstallation of Language Features

registry_key node['windows']['Policy']['TextInput'] do
  values [{
    name: 'AllowLanguageFeaturesUninstall',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow Corporate redirection of Customer Experience Improvement uploads

registry_key node['windows']['Policy']['CorporateSQMURL'] do
  values [{
    name: 'CorporateSQMURL',
    type: :string,
    data: '',
    }]
  action :delete
end

# Tag Windows Customer Experience Improvement data with Study Identifier

registry_key node['windows']['Policy']['StudyId'] do
  values [{
    name: 'StudyId',
    type: :dword,
    data: '',
    }]
  action :delete
end

# Allow antimalware service to remain running always

registry_key node['windows']['Policy']['Defender'] do
  values [{
    name: 'ServiceKeepAlive',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow antimalware service to startup with normal priority

registry_key node['windows']['Policy']['Defender'] do
  values [{
    name: 'AllowFastServiceStartup',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Configure detection for potentially unwanted applications

registry_key node['windows']['Policy']['Defender'] do
  values [{
    name: 'PUAProtection',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Configure local administrator merge behavior for lists

registry_key node['windows']['Policy']['Defender'] do
  values [{
    name: 'DisableLocalAdminMerge',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off routine remediation

registry_key node['windows']['Policy']['Defender'] do
  values [{
    name: 'DisableRoutinelyTakingAction',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off Windows Defender Antivirus

registry_key node['windows']['Policy']['Defender'] do
  values [{
    name: 'DisableAntiSpyware',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Extension Exclusions

registry_key node['windows']['Policy']['Exclusions'] do
  values [{
    name: 'Exclusions_Extensions',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Path Exclusions

registry_key node['windows']['Policy']['Exclusions'] do
  values [{
    name: 'Exclusions_Paths',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Process Exclusions

registry_key node['windows']['Policy']['Exclusions'] do
  values [{
    name: 'Exclusions_Processes',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off Auto Exclusions

registry_key node['windows']['Policy']['Exclusions'] do
  values [{
    name: 'DisableAutoExclusions',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Configure local setting override for reporting to Microsoft MAPS

registry_key node['windows']['Policy']['MAPS'] do
  values [{
    name: 'LocalSettingOverrideSpynetReporting',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Configure the 'Block at First Sight' feature

registry_key node['windows']['Policy']['MAPS'] do
  values [{
    name: 'DisableBlockAtFirstSeen',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Join Microsoft MAPS

registry_key node['windows']['Policy']['MAPS'] do
  values [{
    name: 'SpynetReporting',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Send file samples when further analysis is required

registry_key node['windows']['Policy']['MAPS'] do
  values [{
    name: 'SubmitSamplesConsent',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Configure extended cloud check

registry_key node['windows']['Policy']['MpEngine'] do
  values [{
    name: 'MpBafsExtendedTimeout',
    type: :dword,
    data: 50,
  }]
  recursive true
  action :create
end

# Select cloud protection level

registry_key node['windows']['Policy']['MpEngine'] do
  values [{
    name: 'MpCloudBlockLevel',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Specify additional definition sets for network traffic inspection

registry_key node['windows']['Policy']['IPS'] do
  values [{
    name: 'Nis_Consumers_IPS_sku_differentiation_Signature_Set_Guid',
    type: :dword,
    data: '',
    }]
  action :delete
end

# Turn on definition retirement

registry_key node['windows']['Policy']['DisableSignatureRetirement'] do
  values [{
    name: 'DisableSignatureRetirement',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Monitor file and program activity on your computer

registry_key node['windows']['Policy']['RealTime'] do
  values [{
    name: 'DisableOnAccessProtection',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Scan all downloaded files and attachments

registry_key node['windows']['Policy']['RealTime'] do
  values [{
    name: 'DisableIOAVProtection',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn off real-time protection

registry_key node['windows']['Policy']['RealTime'] do
  values [{
    name: 'DisableRealtimeMonitoring',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on behavior monitoring

registry_key node['windows']['Policy']['RealTime'] do
  values [{
    name: 'DisableBehaviorMonitoring',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on process scanning whenever real-time protection is enabled

registry_key node['windows']['Policy']['RealTime'] do
  values [{
    name: 'DisableScanOnRealtimeEnable',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on raw volume write notifications

registry_key node['windows']['Policy']['RealTime'] do
  values [{
    name: 'DisableRawWriteNotification',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Configure local setting override for the time of day to run a scheduled full scan to complete remediation

registry_key node['windows']['Policy']['Remediation'] do
  values [{
    name: 'LocalSettingOverrideScan_ScheduleTime',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Configure Watson events

registry_key node['windows']['Policy']['Reporting'] do
  values [{
    name: 'DisableGenericRePorts',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Turn off enhanced notifications

registry_key node['windows']['Policy']['Reporting'] do
  values [{
    name: 'DisableEnhancedNotifications',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow users to pause scan

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'AllowPause',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Check for the latest virus and spyware definitions before running a scheduled scan

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'CheckForSignaturesBeforeRunningScan',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Configure local setting override for maximum percentage of CPU utilization

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'LocalSettingOverrideAvgCPULoadFactor',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Configure local setting override for schedule scan day

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'LocalSettingOverrideScheduleDay',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Configure local setting override for scheduled quick scan time

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'LocalSettingOverrideScheduleQuickScanTime',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Configure local setting override for scheduled scan time

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'LocalSettingOverrideScheduleTime',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Configure local setting override for the scan type to use for a scheduled scan

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'LocalSettingOverrideScanParameters',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Configure low CPU priority for scheduled scans

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'LowCpuPriority',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Create a system restore point

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'DisableRestorePoint',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Run full scan on mapped network drives

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'DisableScanningMappedNetworkDrivesForFullScan',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Scan archive files

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'DisableArchiveScanning',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Scan network files

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'DisableScanningNetworkFiles',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Scan packed executables

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'DisablePackedExeScanning',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Scan removable drives

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'DisableRemovableDriveScanning',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Specify the maximum percentage of CPU utilization during a scan

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'AvgCPULoadFactor',
    type: :dword,
    data: 50,
  }]
  recursive true
  action :create
end

# Specify the scan type to use for a scheduled scan

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'ScanParameters',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Specify the time for a daily quick scan

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'ScheduleQuickScanTime',
    type: :dword,
    data: 120,
  }]
  recursive true
  action :create
end

# Specify the time of day to run a scheduled scan

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'ScheduleTime',
    type: :dword,
    data: 120,
  }]
  recursive true
  action :create
end

# Start the scheduled scan only when computer is on but not in use

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'ScanOnlyIfIdle',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on catch-up full scan

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'DisableCatchupFullScan',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on catch-up quick scan

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'DisableCatchupQuickScan',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on e-mail scanning

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'DisableEmailScanning',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on heuristics

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'DisableHeuristics',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Turn on removal of items from scan history folder

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'PurgeItemsAfterDelay',
    type: :dword,
    data: 30,
  }]
  recursive true
  action :create
end

# Turn on reparse point scanning

registry_key node['windows']['Policy']['Scan'] do
  values [{
    name: 'DisableReparsePointScanning',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow definition updates from Microsoft Update

registry_key node['windows']['Policy']['Signature'] do
  values [{
    name: 'ForceUpdateFromMU',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Allow definition updates when running on battery power

registry_key node['windows']['Policy']['Signature'] do
  values [{
    name: 'DisableScheduledSignatureUpdateOnBattery',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow notifications to disable definitions based reports to Microsoft MAPS

registry_key node['windows']['Policy']['Signature'] do
  values [{
    name: 'SignatureDisableNotification',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Allow real-time definition updates based on reports to Microsoft MAPS

registry_key node['windows']['Policy']['Signature'] do
  values [{
    name: 'RealTimeSignatureDelivery',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Check for the latest virus and spyware definitions on startup

registry_key node['windows']['Policy']['Signature'] do
  values [{
    name: 'UpdateOnStartUp',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Define the number of days after which a catch-up definition update is required

registry_key node['windows']['Policy']['Signature'] do
  values [{
    name: 'SignatureUpdateCatchupInterval',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Define the number of days before spyware definitions are considered out of date

registry_key node['windows']['Policy']['Signature'] do
  values [{
    name: 'ASSignatureDue',
    type: :dword,
    data: 7,
  }]
  recursive true
  action :create
end

# Define the number of days before virus definitions are considered out of date

registry_key node['windows']['Policy']['Signature'] do
  values [{
    name: 'AVSignatureDue',
    type: :dword,
    data: 7,
  }]
  recursive true
  action :create
end

# Initiate definition update on startup

registry_key node['windows']['Policy']['Signature'] do
  values [{
    name: 'DisableUpdateOnStartupWithoutEngine',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Specify the interval to check for definition updates

registry_key node['windows']['Policy']['Signature'] do
  values [{
    name: 'SignatureUpdateInterval',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Specify the time to check for definition updates

registry_key node['windows']['Policy']['Signature'] do
  values [{
    name: 'ScheduleTime',
    type: :dword,
    data: 120,
  }]
  recursive true
  action :create
end

# Turn on scan after signature update

registry_key node['windows']['Policy']['Signature'] do
  values [{
    name: 'DisableScanOnUpdate',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Configure Attack Surface Reduction rules

registry_key node['windows']['Policy']['ASR'] do
  values [{
    name: 'ExploitGuard_ASR_Rules',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['ASRRules'] do
  values [{ name: 'd3e037e1-3eb8-44c8-a917-57927947596d', type: :string, data: '1' },
          { name: 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4', type: :string, data: '1' },
          { name: 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550', type: :string, data: '1' },
          { name: 'd4f940ab-401b-4efc-aadc-ad5f3c50688a', type: :string, data: '1' },
          { name: '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', type: :string, data: '1' },
          { name: '3b576869-a4ec-4529-8536-b80a7769e899', type: :string, data: '1' },
          { name: '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84', type: :string, data: '1' },
          { name: '5beb7efe-fd9a-4556-801d-275e5ffc04cc', type: :string, data: '1' },
          { name: '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B', type: :string, data: '1' },
         ]
  action :create
  recursive true
end

# Exclude files and paths from Attack Surface Reduction Rules

registry_key node['windows']['Policy']['ASR'] do
  values [{
    name: 'ExploitGuard_ASR_ASROnlyExclusions',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['ASROnlyExclusions'] do
  values [{ name: 'C:\Temp', type: :string, data: '0' }]
  action :create
  recursive true
end

# Turn on Module Logging

registry_key node['windows']['Policy']['ModuleLogging'] do
  values [{
    name: 'EnableModuleLogging',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

registry_key node['windows']['Policy']['ModuleNames'] do
  values [{ name: 'Module Names', type: :string, data: 'Microsoft.PowerShell.*' },
          { name: 'Module Names', type: :string, data: 'Microsoft.WSMan.Management' },
  ]
  action :create
  recursive true
end
