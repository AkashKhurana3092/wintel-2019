#
# Cookbook:: wintel-2019
# Recipe:: security
#
# Copyright:: 2022, The Authors, All Rights Reserved.

# Account lockout threshold

windows_security_policy 'LockoutBadCount' do
  secvalue '3'
  action :set
end

# Account lockout duration

windows_security_policy 'LockoutDuration' do
  secvalue '60'
  action :set
end

# Reset account lockout counter after

windows_security_policy 'ResetLockoutCount' do
  secvalue       '20'
  action         :set
end

# Password Policy

dsc_module 'SecurityPolicyDSC' do
  dsc_resource 'MSFT_AccountPolicy'
  action :import
end

pass_policy_hash = [{ option: 'Enforce_password_history', value: 24 },
    { option: 'Maximum_Password_Age', value: 30 },
    { option: 'Minimum_Password_Age', value: 1 },
    { option: 'Minimum_Password_Length', value: 14 },
    { option: 'Password_must_meet_complexity_requirements', value: 'Enabled' },
    { option: 'Store_passwords_using_reversible_encryption', value: 'Disabled' },
   ]

pass_policy_hash.each do |pol|
  dsc_password_policy pol[:option] do
    passopt pol[:option]
    passvalue pol[:value]
  end
end

# Accounts: Administrator account status

windows_security_policy 'EnableAdminAccount' do
  secvalue '0'
  action :set
end

# Accounts: Block Microsoft accounts

registry_key node['windows']['Policy']['NoConnectedUser'] do
  values [{
    name: 'NoConnectedUser',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Accounts: Guest account status

windows_security_policy 'EnableGuestAccount' do
  secvalue '0'
  action :set
end

# Accounts: Limit local account use of blank passwords to console logon only

registry_key node['windows']['Policy']['LimitBlankPasswordUse'] do
  values [{
    name: 'LimitBlankPasswordUse',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Accounts: Rename administrator account

windows_security_policy 'NewAdministratorName' do
  secvalue '00000001'
  action :set
end

# Accounts: Rename guest account

windows_security_policy 'NewGuestName' do
  secvalue 'NotInUse'
  action :set
end

# Audit: Audit the access of global system objects

registry_key node['windows']['Policy']['AuditBaseObjects'] do
  values [{
    name: 'AuditBaseObjects',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings

registry_key node['windows']['Policy']['SCENoApplyLegacyAuditPolicy'] do
  values [{
    name: 'SCENoApplyLegacyAuditPolicy',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Audit: Shut down system immediately if unable to log security audits

registry_key node['windows']['Policy']['CrashOnAuditFail'] do
  values [{
    name: 'CrashOnAuditFail',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# DCOM: Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax

registry_key node['windows']['Policy']['MachineAccessRestriction'] do
  values [{
    name: 'MachineAccessRestriction',
    type: :dword,
    data: 'delete',
  }]
  recursive true
  action :create
end

# DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax

registry_key node['windows']['Policy']['MachineLaunchRestriction'] do
  values [{
    name: 'MachineLaunchRestriction',
    type: :dword,
    data: 'delete',
  }]
  recursive true
  action :create
end

# Devices: Allow undock without having to log on

registry_key node['windows']['Policy']['UndockWithoutLogon'] do
  values [{
    name: 'UndockWithoutLogon',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Devices: Allowed to format and eject removable media

registry_key node['windows']['Policy']['AllocateDASD'] do
  values [{
    name: 'AllocateDASD',
    type: :string,
    data: 'Administrators',
  }]
  recursive true
  action :create
end

# Devices: Prevent users from installing printer drivers

registry_key node['windows']['Policy']['AddPrinterDrivers'] do
  values [{
    name: 'AddPrinterDrivers',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Devices: Restrict CD-ROM access to locally logged-on user only

registry_key node['windows']['Policy']['AllocateCDRoms'] do
  values [{
    name: 'AllocateCDRoms',
    type: :string,
    data: 1,
  }]
  recursive true
  action :create
end

# Devices: Restrict floppy access to locally logged-on user only

registry_key node['windows']['Policy']['AllocateFloppies'] do
  values [{
    name: 'AllocateFloppies',
    type: :string,
    data: 1,
  }]
  recursive true
  action :create
end

# Domain controller: Allow server operators to schedule tasks

registry_key node['windows']['Policy']['SubmitControl'] do
  values [{
    name: 'SubmitControl',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Domain controller: LDAP server signing requirements

registry_key node['windows']['Policy']['LDAPServerIntegrity'] do
  values [{
    name: 'LDAPServerIntegrity',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Domain controller: Refuse machine account password change

registry_key node['windows']['Policy']['RefusePasswordChange'] do
  values [{
    name: 'RefusePasswordChange',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Domain member: Digitally encrypt or sign secure channel data (always)

registry_key node['windows']['Policy']['RequireSignOrSeal'] do
  values [{
    name: 'RequireSignOrSeal',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Domain member: Digitally encrypt secure channel data (when possible)

registry_key node['windows']['Policy']['SealSecureChannel'] do
  values [{
    name: 'SealSecureChannel',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Domain member: Digitally sign secure channel data (when possible)

registry_key node['windows']['Policy']['SignSecureChannel'] do
  values [{
    name: 'SignSecureChannel',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Domain member: Disable machine account password changes

registry_key node['windows']['Policy']['DisablePasswordChange'] do
  values [{
    name: 'DisablePasswordChange',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Domain member: Maximum machine account password age

registry_key node['windows']['Policy']['MaximumPasswordAge'] do
  values [{
    name: 'MaximumPasswordAge',
    type: :dword,
    data: '30e',
  }]
  recursive true
  action :create
end

# Domain member: Require strong (Windows 2000 or later) session key

registry_key node['windows']['Policy']['RequireStrongKey'] do
  values [{
    name: 'RequireStrongKey',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Interactive logon: Display user information when the session is locked

registry_key node['windows']['Policy']['DontDisplayLockedUserId'] do
  values [{
    name: 'DontDisplayLockedUserId',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Interactive logon: Do not require CTRL+ALT+DEL

registry_key node['windows']['Policy']['DisableCAD'] do
  values [{
    name: 'DisableCAD',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Interactive logon: Don't display last signed-in

registry_key node['windows']['Policy']['DontDisplayLastUserName'] do
  values [{
    name: 'DontDisplayLastUserName',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Interactive logon: Don't display username at sign-in

registry_key node['windows']['Policy']['DontDisplayUserName'] do
  values [{
    name: 'DontDisplayUserName',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Interactive logon: Machine account lockout threshold

registry_key node['windows']['Policy']['MaxDevicePasswordFailedAttempts'] do
  values [{
    name: 'MaxDevicePasswordFailedAttempts',
    type: :dword,
    data: 3,
  }]
  recursive true
  action :create
end

# Interactive logon: Machine inactivity limit

registry_key node['windows']['Policy']['InactivityTimeoutSecs'] do
  values [{
    name: 'InactivityTimeoutSecs',
    type: :dword,
    data: 900,
  }]
  recursive true
  action :create
end

# Interactive logon: Message text for users attempting to log on

registry_key node['windows']['Policy']['LegalNoticeText'] do
  values [{
    name: 'LegalNoticeText',
    type: :string,
    data: 'Programs and data held on this system are PRIVATE PROPERTY and may be accessed only by authorised users for purposes which have been authorised.
    Unauthorised access to this computer material contravenes company rules, is a criminal offence and may bring disciplinary action by the company, as well as incur criminal penalties and civil damages. If you are not an authorised user, proceed no further.
    This system is subject to routine monitoring of all activities.',
  }]
  recursive true
  action :create
end

# Interactive logon: Message title for users attempting to log on

registry_key node['windows']['Policy']['LegalNoticeCaption'] do
  values [{
    name: 'LegalNoticeCaption',
    type: :string,
    data: 'UNAUTHORISED ACCESS WARNING!',
  }]
  recursive true
  action :create
end

# Interactive logon: Number of previous logons to cache (in case domain controller is not available)

registry_key node['windows']['Policy']['CachedLogonsCount'] do
  values [{
    name: 'CachedLogonsCount',
    type: :string,
    data: 0,
  }]
  recursive true
  action :create
end

# Interactive logon: Prompt user to change password before expiration

registry_key node['windows']['Policy']['PasswordExpiryWarning'] do
  values [{
    name: 'PasswordExpiryWarning',
    type: :dword,
    data: 5,
  }]
  recursive true
  action :create
end

# Interactive logon: Require Domain Controller authentication to unlock workstation

registry_key node['windows']['Policy']['ForceUnlockLogon'] do
  values [{
    name: 'ForceUnlockLogon',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Interactive logon: Require Windows Hello for Business or smart card

registry_key node['windows']['Policy']['ScForceOption'] do
  values [{
    name: 'ScForceOption',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Interactive logon: Smart card removal behavior

registry_key node['windows']['Policy']['ScRemoveOption'] do
  values [{
    name: 'ScRemoveOption',
    type: :string,
    data: 1,
  }]
  recursive true
  action :create
end

# Microsoft network client: Digitally sign communications (always) ##### Need to be Fixed

registry_key node['windows']['Policy']['Client']['RequireSecuritySignature'] do
  values [{
    name: 'RequireSecuritySignature',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Microsoft network client: Digitally sign communications (if server agrees) ##### Need to be Fixed

registry_key node['windows']['Policy']['Client']['EnableSecuritySignature'] do
  values [{
    name: 'EnableSecuritySignature',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Microsoft network client: Send unencrypted password to third-party SMB servers

registry_key node['windows']['Policy']['EnablePlainTextPassword'] do
  values [{
    name: 'EnablePlainTextPassword',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Microsoft network server: Amount of idle time required before suspending session

registry_key node['windows']['Policy']['AutoDisconnect'] do
  values [{
    name: 'AutoDisconnect',
    type: :dword,
    data: 15,
  }]
  recursive true
  action :create
end

# Microsoft network server: Attempt S4U2Self to obtain claim information

registry_key node['windows']['Policy']['EnableS4U2SelfForClaims'] do
  values [{
    name: 'EnableS4U2SelfForClaims',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# Microsoft network server: Digitally sign communications (always)

registry_key node['windows']['Policy']['RequireSecuritySignature'] do
  values [{
    name: 'RequireSecuritySignature',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Microsoft network server: Digitally sign communications (if client agrees)

registry_key node['windows']['Policy']['EnableSecuritySignature'] do
  values [{
    name: 'EnableSecuritySignature',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Microsoft network server: Disconnect clients when logon hours expire

registry_key node['windows']['Policy']['EnableForcedLogOff'] do
  values [{
    name: 'EnableForcedLogOff',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Microsoft network server: Server SPN target name validation level

registry_key node['windows']['Policy']['SmbServerNameHardeningLevel'] do
  values [{
    name: 'SmbServerNameHardeningLevel',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Network access: Do not allow anonymous enumeration of SAM accounts

registry_key node['windows']['Policy']['RestrictAnonymousSAM'] do
  values [{
    name: 'RestrictAnonymousSAM',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Network access: Do not allow anonymous enumeration of SAM accounts and shares

registry_key node['windows']['Policy']['RestrictAnonymous'] do
  values [{
    name: 'RestrictAnonymous',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Network access: Do not allow storage of passwords and credentials for network authentication

registry_key node['windows']['Policy']['DisableDomainCreds'] do
  values [{
    name: 'DisableDomainCreds',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Network access: Let Everyone permissions apply to anonymous users

registry_key node['windows']['Policy']['EveryoneIncludesAnonymous'] do
  values [{
    name: 'EveryoneIncludesAnonymous',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Network access: Named Pipes that can be accessed anonymously

registry_key node['windows']['Policy']['NullSessionPipes'] do
  values [{
    name: 'NullSessionPipes',
    type: :multi_string,
    data: %w(),
  }]
  recursive true
  action :create
end

# Network access: Remotely accessible registry paths ##### Need to be Fixed

registry_key node['windows']['Policy']['AllowedExactPaths']['Machine'] do
  values [
    { name: 'System\\CurrentControlSet\\Control\\ProductOptions', type: :multi_string, data: %w() },
    { name: 'System\\CurrentControlSet\\Control\\Server Applications', type: :multi_string, data: %w() },
    { name: 'Software\\Microsoft\\Windows NT\\CurrentVersion', type: :multi_string, data: %w() },
  ]
  recursive true
  action :create
end

# Network access: Remotely accessible registry paths and sub-paths ##### Need to be Fixed

registry_key node['windows']['Policy']['AllowedPaths']['Machine'] do
  values [
    { name: 'System\\CurrentControlSet\\Control\\Print\\Printers', type: :multi_string, data: %w() },
    { name: 'System\\CurrentControlSet\\Services\\Eventlog', type: :multi_string, data: %w() },
    { name: 'Software\\Microsoft\\OLAP Server', type: :multi_string, data: %w() },
    { name: 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Print', type: :multi_string, data: %w() },
    { name: 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows', type: :multi_string, data: %w() },
    { name: 'System\\CurrentControlSet\\Control\\ContentIndex', type: :multi_string, data: %w() },
    { name: 'System\\CurrentControlSet\\Control\\Terminal Server', type: :multi_string, data: %w() },
    { name: 'System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig', type: :multi_string, data: %w() },
    { name: 'System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration', type: :multi_string, data: %w() },
    { name: 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib', type: :multi_string, data: %w() },
    { name: 'System\\CurrentControlSet\\Services\\SysmonLog', type: :multi_string, data: %w() },
  ]
  recursive true
  action :create
end

# Network access: Restrict anonymous access to Named Pipes and Shares

registry_key node['windows']['Policy']['RestrictNullSessAccess'] do
  values [{
    name: 'RestrictNullSessAccess',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Network access: Restrict clients allowed to make remote calls to SAM

registry_key node['windows']['Policy']['RestrictRemoteSAM'] do
  values [{
    name: 'RestrictRemoteSAM',
    type: :string,
    data: 'O:BAG:BAD:(A;;RC;;;BA)',
  }]
  recursive true
  action :create
end

# Network access: Shares that can be accessed anonymously

registry_key node['windows']['Policy']['NullSessionShares'] do
  values [{
    name: 'NullSessionShares',
    type: :multi_string,
    data: %w(),
  }]
  recursive true
  action :create
end

# Network access: Sharing and security model for local accounts

registry_key node['windows']['Policy']['ForceGuest'] do
  values [{
    name: 'ForceGuest',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Network security: Allow Local System to use computer identity for NTLM

registry_key node['windows']['Policy']['UseMachineId'] do
  values [{
    name: 'UseMachineId',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Network security: Allow LocalSystem NULL session fallback

registry_key node['windows']['Policy']['allownullsessionfallback'] do
  values [{
    name: 'allownullsessionfallback',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Network security: Allow PKU2U authentication requests to this computer to use online identities.

registry_key node['windows']['Policy']['AllowOnlineID'] do
  values [{
    name: 'AllowOnlineID',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Network security: Configure encryption types allowed for Kerberos

registry_key node['windows']['Policy']['SupportedEncryptionTypes'] do
  values [{
    name: 'SupportedEncryptionTypes',
    type: :dword,
    data: 24,
  }]
  recursive true
  action :create
end

# Network security: Do not store LAN Manager hash value on next password change

registry_key node['windows']['Policy']['NoLMHash'] do
  values [{
    name: 'NoLMHash',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Network security: LAN Manager authentication level

registry_key node['windows']['Policy']['LmCompatibilityLevel'] do
  values [{
    name: 'LmCompatibilityLevel',
    type: :dword,
    data: 5,
  }]
  recursive true
  action :create
end

# Network security: LDAP client signing requirements

registry_key node['windows']['Policy']['LDAPClientIntegrity'] do
  values [{
    name: 'LDAPClientIntegrity',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Network security: Minimum session security for NTLM SSP based (including secure RPC) clients

registry_key node['windows']['Policy']['NTLMMinClientSec'] do
  values [{
    name: 'NTLMMinClientSec',
    type: :dword,
    data: 537395200,
  }]
  recursive true
  action :create
end

# Network security: Minimum session security for NTLM SSP based (including secure RPC) servers

registry_key node['windows']['Policy']['NTLMMinServerSec'] do
  values [{
    name: 'NTLMMinServerSec',
    type: :dword,
    data: 537395200,
  }]
  recursive true
  action :create
end

# Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication

registry_key node['windows']['Policy']['ClientAllowedNTLMServers'] do
  values [{
    name: 'ClientAllowedNTLMServers',
    type: :multi_string,
    data: '',
    }]
  action :delete
end

# Network security: Restrict NTLM: Add server exceptions in this domain

registry_key node['windows']['Policy']['DCAllowedNTLMServers'] do
  values [{
    name: 'DCAllowedNTLMServers',
    type: :multi_string,
    data: '',
    }]
  action :delete
end

# Network security: Restrict NTLM: Audit Incoming NTLM Traffic

registry_key node['windows']['Policy']['AuditReceivingNTLMTraffic'] do
  values [{
    name: 'AuditReceivingNTLMTraffic',
    type: :dword,
    data: '',
    }]
  action :delete
end

# Network security: Restrict NTLM: Audit NTLM authentication in this domain

registry_key node['windows']['Policy']['AuditNTLMInDomain'] do
  values [{
    name: 'AuditNTLMInDomain',
    type: :dword,
    data: '',
    }]
  action :delete
end

# Network security: Restrict NTLM: Incoming NTLM traffic

registry_key node['windows']['Policy']['RestrictReceivingNTLMTraffic'] do
  values [{
    name: 'RestrictReceivingNTLMTraffic',
    type: :dword,
    data: '',
    }]
  action :delete
end

# Network security: Restrict NTLM: NTLM authentication in this domain

registry_key node['windows']['Policy']['RestrictNTLMInDomain'] do
  values [{
    name: 'RestrictNTLMInDomain',
    type: :dword,
    data: '',
    }]
  action :delete
end

# Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers

registry_key node['windows']['Policy']['RestrictSendingNTLMTraffic'] do
  values [{
    name: 'RestrictSendingNTLMTraffic',
    type: :dword,
    data: '',
    }]
  action :delete
end

# Recovery console: Allow automatic administrative logon

registry_key node['windows']['Policy']['SecurityLevel'] do
  values [{
    name: 'SecurityLevel',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Recovery console: Allow floppy copy and access to all drives and all folders

registry_key node['windows']['Policy']['SetCommand'] do
  values [{
    name: 'SetCommand',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Shutdown: Allow system to be shut down without having to log on

registry_key node['windows']['Policy']['ShutdownWithoutLogon'] do
  values [{
    name: 'ShutdownWithoutLogon',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Shutdown: Clear virtual memory pagefile

registry_key node['windows']['Policy']['ClearPageFileAtShutdown'] do
  values [{
    name: 'ClearPageFileAtShutdown',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# System cryptography: Force strong key protection for user keys stored on the computer

registry_key node['windows']['Policy']['ForceKeyProtection'] do
  values [{
    name: 'ForceKeyProtection',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing

registry_key node['windows']['Policy']['Enabled'] do
  values [{
    name: 'Enabled',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# System objects: Require case insensitivity for non-Windows subsystems

registry_key node['windows']['Policy']['ObCaseInsensitive'] do
  values [{
    name: 'ObCaseInsensitive',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)

registry_key node['windows']['Policy']['ProtectionMode'] do
  values [{
    name: 'ProtectionMode',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# System settings: Optional subsystems

registry_key node['windows']['Policy']['optional'] do
  values [{
    name: 'optional',
    type: :multi_string,
    data: %w(),
  }]
  recursive true
  action :create
end

# System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies

registry_key node['windows']['Policy']['AuthenticodeEnabled'] do
  values [{
    name: 'AuthenticodeEnabled',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# User Account Control: Admin Approval Mode for the Built-in Administrator account

registry_key node['windows']['Policy']['FilterAdministratorToken'] do
  values [{
    name: 'FilterAdministratorToken',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop

registry_key node['windows']['Policy']['EnableUIADesktopToggle'] do
  values [{
    name: 'EnableUIADesktopToggle',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode

registry_key node['windows']['Policy']['ConsentPromptBehaviorAdmin'] do
  values [{
    name: 'ConsentPromptBehaviorAdmin',
    type: :dword,
    data: 2,
  }]
  recursive true
  action :create
end

# User Account Control: Behavior of the elevation prompt for standard users

registry_key node['windows']['Policy']['ConsentPromptBehaviorUser'] do
  values [{
    name: 'ConsentPromptBehaviorUser',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# User Account Control: Detect application installations and prompt for elevation

registry_key node['windows']['Policy']['EnableInstallerDetection'] do
  values [{
    name: 'EnableInstallerDetection',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# User Account Control: Only elevate executables that are signed and validated

registry_key node['windows']['Policy']['ValidateAdminCodeSignatures'] do
  values [{
    name: 'ValidateAdminCodeSignatures',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# User Account Control: Only elevate UIAccess applications that are installed in secure locations

registry_key node['windows']['Policy']['EnableSecureUIAPaths'] do
  values [{
    name: 'EnableSecureUIAPaths',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# User Account Control: Run all administrators in Admin Approval Mode

registry_key node['windows']['Policy']['EnableLUA'] do
  values [{
    name: 'EnableLUA',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# User Account Control: Switch to the secure desktop when prompting for elevation

registry_key node['windows']['Policy']['PromptOnSecureDesktop'] do
  values [{
    name: 'PromptOnSecureDesktop',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# User Account Control: Virtualize file and registry write failures to per-user locations

registry_key node['windows']['Policy']['EnableVirtualization'] do
  values [{
    name: 'EnableVirtualization',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Network access: Allow anonymous SID/Name translation

windows_security_policy 'LSAAnonymousNameLookup' do
  secvalue '0'
  action :set
end

# Network security: Force logoff when logon hours expire

windows_security_policy 'ForceLogoffWhenHourExpire' do
  secvalue '1'
  action :set
end
