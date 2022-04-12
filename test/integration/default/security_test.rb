# Chef InSpec test for recipe wintel-2019::security

# The Chef InSpec reference, with examples and extensive documentation, can be
# found at https://docs.chef.io/inspec/resources/

# Account lockout threshold

control 'Security_01' do
  describe security_policy do
    its('LockoutBadCount') { should eq 3 }
  end
end

# Account lockout duration

control 'Security_02' do
  describe security_policy do
    its('LockoutDuration') { should eq 60 }
  end
end

# Reset account lockout counter after

control 'Security_03' do
  describe security_policy do
    its('ResetLockoutCount') { should eq 20 }
  end
end

# Accounts: Administrator account status

control 'Security_04' do
  describe security_policy do
    its('EnableAdminAccount') { should eq 0 }
  end
end

# Accounts: Block Microsoft accounts

control 'Security_05' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('NoConnectedUser') { should eq 3 }
  end
end

# Accounts: Guest account status

control 'Security_06' do
  describe security_policy do
    its('EnableGuestAccount') { should eq 0 }
  end
end

# Accounts: Limit local account use of blank passwords to console logon only

control 'Security_07' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
    its('LimitBlankPasswordUse') { should eq 1 }
  end
end

# Accounts: Rename administrator account

control 'Security_08' do
  describe security_policy do
    its('NewAdministratorName') { should eq '00000001' }
  end
end

# Accounts: Rename guest account

control 'Security_09' do
  describe security_policy do
    its('NewGuestName') { should eq 'NotInUse' }
  end
end

# Audit: Audit the access of global system objects

control 'Security_10' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
    its('AuditBaseObjects') { should eq 0 }
  end
end

# Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings

control 'Security_11' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
    its('SCENoApplyLegacyAuditPolicy') { should eq 0 }
  end
end

# Audit: Shut down system immediately if unable to log security audits

control 'Security_12' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
    its('CrashOnAuditFail') { should eq 0 }
  end
end

# DCOM: Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax

control 'Security_13' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\policies\\Microsoft\\windows NT\\DCOM' do
    its('MachineAccessRestriction') { should eq 0 }
  end
end

# DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax

control 'Security_14' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\policies\\Microsoft\\windows NT\\DCOM' do
    its('MachineLaunchRestriction') { should eq 0 }
  end
end

# Devices: Allow undock without having to log on

control 'Security_15' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('UndockWithoutLogon') { should eq 0 }
  end
end

# Devices: Allowed to format and eject removable media

control 'Security_16' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
    its('AllocateDASD') { should eq 'Administrators' }
  end
end

# Devices: Prevent users from installing printer drivers

control 'Security_17' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers' do
    its('AddPrinterDrivers') { should eq 1 }
  end
end

# Devices: Restrict CD-ROM access to locally logged-on user only

control 'Security_18' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
    its('AllocateCDRoms') { should eq '1' }
  end
end

# Devices: Restrict floppy access to locally logged-on user only

control 'Security_19' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
    its('AllocateFloppies') { should eq '1' }
  end
end

# Domain controller: Allow server operators to schedule tasks

control 'Security_20' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
    its('SubmitControl') { should eq 0 }
  end
end

# Domain controller: LDAP server signing requirements

control 'Security_21' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters' do
    its('LDAPServerIntegrity') { should eq 2 }
  end
end

# Domain controller: Refuse machine account password changes

control 'Security_22' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
    its('RefusePasswordChange') { should eq 0 }
  end
end

# Domain member: Digitally encrypt or sign secure channel data (always)

control 'Security_23' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
    its('RequireSignOrSeal') { should eq 1 }
  end
end

# Domain member: Digitally encrypt secure channel data (when possible)

control 'Security_24' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
    its('SealSecureChannel') { should eq 1 }
  end
end

# Domain member: Digitally sign secure channel data (when possible)

control 'Security_25' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
    its('SignSecureChannel') { should eq 1 }
  end
end

# Domain member: Disable machine account password changes

control 'Security_26' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
    its('DisablePasswordChange') { should eq 0 }
  end
end

# Domain member: Maximum machine account password age

control 'Security_27' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
    its('MaximumPasswordAge') { should eq 30 }
  end
end

# Domain member: Require strong (Windows 2000 or later) session key

control 'Security_28' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
    its('RequireStrongKey') { should eq 1 }
  end
end

# Interactive logon: Display user information when the session is locked

control 'Security_29' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('DontDisplayLockedUserId') { should eq 2 }
  end
end

# Interactive logon: Do not require CTRL+ALT+DEL

control 'Security_30' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('DisableCAD') { should eq 0 }
  end
end

# Interactive logon: Don't display last signed-in

control 'Security_31' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('DontDisplayLastUserName') { should eq 1 }
  end
end

# Interactive logon: Don't display username at sign-in

control 'Security_32' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('DontDisplayUserName') { should eq 1 }
  end
end

# Interactive logon: Machine account lockout threshold

control 'Security_33' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('MaxDevicePasswordFailedAttempts') { should eq 3 }
  end
end

# Interactive logon: Machine inactivity limit

control 'Security_34' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('InactivityTimeoutSecs') { should eq 900 }
  end
end

# Interactive logon: Message text for users attempting to log on

control 'Security_35' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('LegalNoticeText') do
      should eq "Programs and data held on this system are PRIVATE PROPERTY and may be accessed only by authorised users for purposes which have been authorised.
    Unauthorised access to this computer material contravenes company rules, is a criminal offence and may bring disciplinary action by the company, as well as incur criminal penalties and civil damages. If you are not an authorised user, proceed no further.
    This system is subject to routine monitoring of all activities."
    end
  end
end

# Interactive logon: Message title for users attempting to log on

control 'Security_36' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('LegalNoticeCaption') { should eq 'UNAUTHORISED ACCESS WARNING!' }
  end
end

# Interactive logon: Number of previous logons to cache (in case domain controller is not available)

control 'Security_37' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
    its('CachedLogonsCount') { should eq '0' }
  end
end

# Interactive logon: Prompt user to change password before expiration

control 'Security_38' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
    its('PasswordExpiryWarning') { should eq 5 }
  end
end

# Interactive logon: Require Domain Controller authentication to unlock workstation

control 'Security_39' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
    its('ForceUnlockLogon') { should eq 1 }
  end
end

# Interactive logon: Require Windows Hello for Business or smart card

control 'Security_40' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('ScForceOption') { should eq 0 }
  end
end

# Interactive logon: Smart card removal behavior

control 'Security_41' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
    its('ScRemoveOption') { should eq '1' }
  end
end

# Microsoft network client: Digitally sign communications (always)

control 'Security_42' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' do
    its('RequireSecuritySignature') { should eq 1 }
  end
end

# Microsoft network client: Digitally sign communications (if server agrees)

control 'Security_43' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' do
    its('EnableSecuritySignature') { should eq 1 }
  end
end

# Microsoft network client: Send unencrypted password to third-party SMB servers

control 'Security_44' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' do
    its('EnablePlainTextPassword') { should eq 0 }
  end
end

# Microsoft network server: Amount of idle time required before suspending session

control 'Security_45' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' do
    its('AutoDisconnect') { should eq 15 }
  end
end

# Microsoft network server: Attempt S4U2Self to obtain claim information

control 'Security_46' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' do
    its('EnableS4U2SelfForClaims') { should eq 2 }
  end
end

# Microsoft network server: Digitally sign communications (always)

control 'Security_47' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' do
    its('RequireSecuritySignature') { should eq 1 }
  end
end

# Microsoft network server: Digitally sign communications (if client agrees)

control 'Security_48' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' do
    its('EnableSecuritySignature') { should eq 1 }
  end
end

#  Microsoft network server: Disconnect clients when logon hours expire

control 'Security_49' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' do
    its('EnableForcedLogOff') { should eq 1 }
  end
end

# Microsoft network server: Server SPN target name validation level

control 'Security_50' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' do
    its('SmbServerNameHardeningLevel') { should eq 1 }
  end
end

# Network access: Allow anonymous SID/Name translation

control 'Security_51' do
  describe security_policy do
    its('LSAAnonymousNameLookup') { should eq 0 }
  end
end

# Network access: Do not allow anonymous enumeration of SAM accounts

control 'Security_52' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
    its('RestrictAnonymousSAM') { should eq 1 }
  end
end

# Network access: Do not allow anonymous enumeration of SAM accounts and shares

control 'Security_53' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
    its('RestrictAnonymous') { should eq 1 }
  end
end

# Network access: Do not allow storage of passwords and credentials for network authentication

control 'Security_54' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
    its('DisableDomainCreds') { should eq 1 }
  end
end

# Network access: Let Everyone permissions apply to anonymous users

control 'Security_55' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
    its('EveryoneIncludesAnonymous') { should eq 0 }
  end
end

# Network access: Named Pipes that can be accessed anonymously

control 'Security_56' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' do
    its('NullSessionPipes') { should eq [''] }
  end
end

# Network access: Remotely accessible registry paths

control 'Security_57' do
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths').Machine&.reject { |value| value =~ /^((System\\CurrentControlSet\\Control\\ProductOptions)|(System\\CurrentControlSet\\Control\\Server Applications)|(Software\\Microsoft\\Windows NT\\CurrentVersion))$/ } || [] do
    it { should be_empty }
  end
end

# Network access: Remotely accessible registry paths and sub-paths

control 'Security_58' do
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths').Machine&.reject { |value| value =~ /^((System\\CurrentControlSet\\Control\\Print\\Printers)|(System\\CurrentControlSet\\Services\\Eventlog)|(Software\\Microsoft\\OLAP Server)|(Software\\Microsoft\\Windows NT\\CurrentVersion\\Print)|(Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows)|(System\\CurrentControlSet\\Control\\ContentIndex)|(System\\CurrentControlSet\\Control\\Terminal Server)|(System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig)|(System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration)|(Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib)|(System\\CurrentControlSet\\Services\\SysmonLog))$/ } || [] do
    it { should be_empty }
  end
end

# Network access: Restrict anonymous access to Named Pipes and Shares

control 'Security_59' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' do
    its('RestrictNullSessAccess') { should eq 1 }
  end
end

# Network access: Restrict clients allowed to make remote calls to SAM

control 'Security_60' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
    its('RestrictRemoteSAM') { should eq 'O:BAG:BAD:(A;;RC;;;BA)' }
  end
end

# Network access: Shares that can be accessed anonymously

control 'Security_61' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' do
    its('NullSessionShares') { should eq [''] }
  end
end

# Network access: Sharing and security model for local accounts

control 'Security_62' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
    its('ForceGuest') { should eq 0 }
  end
end

# Network security: Allow Local System to use computer identity for NTLM

control 'Security_63' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
    its('UseMachineId') { should eq 1 }
  end
end

# Network security: Allow LocalSystem NULL session fallback

control 'Security_64' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
    its('allownullsessionfallback') { should eq 0 }
  end
end

# Network security: Allow PKU2U authentication requests to this computer to use online identities.

control 'Security_65' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\pku2u' do
    its('AllowOnlineID') { should eq 0 }
  end
end

# Network security: Configure encryption types allowed for Kerberos

control 'Security_66' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters' do
    its('SupportedEncryptionTypes') { should eq 24 }
  end
end

# Network security: Do not store LAN Manager hash value on next password change

control 'Security_67' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
    its('NoLMHash') { should eq 1 }
  end
end

# Network security: Force logoff when logon hours expire

control 'Security_68' do
  describe security_policy do
    its('ForceLogoffWhenHourExpire') { should eq 1 }
  end
end

# Network security: LAN Manager authentication level

control 'Security_69' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
    its('LmCompatibilityLevel') { should eq 5 }
  end
end

# Network security: LDAP client signing requirements

control 'Security_70' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LDAP' do
    its('LDAPClientIntegrity') { should eq 1 }
  end
end

# Network security: Minimum session security for NTLM SSP based (including secure RPC) clients

control 'Security_71' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
    its('NTLMMinServerSec') { should eq 537395200 }
  end
end

# Network security: Minimum session security for NTLM SSP based (including secure RPC) servers

control 'Security_72' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
    its('NTLMMinServerSec') { should eq 537395200 }
  end
end

# Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication

control 'Security_73' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
    its('ClientAllowedNTLMServers') { should cmp nil }
  end
end

# Network security: Restrict NTLM: Add server exceptions in this domain

control 'Security_74' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
    its('DCAllowedNTLMServers') { should cmp nil }
  end
end

# Network security: Restrict NTLM: Audit Incoming NTLM Traffic

control 'Security_75' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
    its('AuditReceivingNTLMTraffic') { should cmp nil }
  end
end

# Network security: Restrict NTLM: Audit NTLM authentication in this domain

control 'Security_76' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
    its('AuditNTLMInDomain') { should cmp nil }
  end
end

# Network security: Restrict NTLM: Incoming NTLM traffic

control 'Security_77' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
    its('RestrictReceivingNTLMTraffic') { should cmp nil }
  end
end

# Network security: Restrict NTLM: NTLM authentication in this domain

control 'Security_78' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
    its('RestrictNTLMInDomain') { should cmp nil }
  end
end

# Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers

control 'Security_79' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
    its('RestrictSendingNTLMTraffic') { should cmp nil }
  end
end

# Recovery console: Allow automatic administrative logon

control 'Security_80' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole' do
    its('SecurityLevel') { should eq 0 }
  end
end

# Recovery console: Allow floppy copy and access to all drives and all folders

control 'Security_81' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole' do
    its('SetCommand') { should eq 0 }
  end
end

# Shutdown: Allow system to be shut down without having to log on

control 'Security_82' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('ShutdownWithoutLogon') { should eq 0 }
  end
end

# Shutdown: Clear virtual memory pagefile

control 'Security_84' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management' do
    its('ClearPageFileAtShutdown') { should eq 0 }
  end
end

# System cryptography: Force strong key protection for user keys stored on the computer

control 'Security_85' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Cryptography' do
    its('ForceKeyProtection') { should eq 2 }
  end
end

# System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing

control 'Security_86' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy' do
    its('Enabled') { should eq 1 }
  end
end

# System objects: Require case insensitivity for non-Windows subsystems

control 'Security_87' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel' do
    its('ObCaseInsensitive') { should eq 1 }
  end
end

# System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)

control 'Security_88' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' do
    its('ProtectionMode') { should eq 1 }
  end
end

# System settings: Optional subsystems

control 'Security_89' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SubSystems' do
    its('optional') { should eq [] }
  end
end

# System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies

control 'Security_90' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers' do
    its('AuthenticodeEnabled') { should eq 0 }
  end
end

# User Account Control: Admin Approval Mode for the Built-in Administrator account

control 'Security_91' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('FilterAdministratorToken') { should eq 1 }
  end
end

# User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop

control 'Security_92' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('EnableUIADesktopToggle') { should eq 0 }
  end
end

# User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode

control 'Security_93' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('ConsentPromptBehaviorAdmin') { should eq 2 }
  end
end

# User Account Control: Behavior of the elevation prompt for standard users

control 'Security_94' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('ConsentPromptBehaviorUser') { should eq 0 }
  end
end

# User Account Control: Detect application installations and prompt for elevation

control 'Security_95' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('EnableInstallerDetection') { should eq 1 }
  end
end

# User Account Control: Only elevate executables that are signed and validated

control 'Security_96' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('ValidateAdminCodeSignatures') { should eq 0 }
  end
end

# User Account Control: Only elevate UIAccess applications that are installed in secure locations

control 'Security_97' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('EnableSecureUIAPaths') { should eq 1 }
  end
end

# User Account Control: Run all administrators in Admin Approval Mode

control 'Security_98' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('EnableLUA') { should eq 1 }
  end
end

# User Account Control: Switch to the secure desktop when prompting for elevation

control 'Security_99' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('PromptOnSecureDesktop') { should eq 0 }
  end
end

# User Account Control: Virtualize file and registry write failures to per-user locations

control 'Security_100' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
    its('EnableVirtualization') { should eq 1 }
  end
end

# # Password Policy: Enforce password history

# control 'Security_101' do
#   describe security_policy do
#     its('PasswordHistorySize') { should be >= 24 }
#   end
# end

# # Password Policy: Maximum password age

# control 'Security_102' do
#   describe security_policy do
#     its('MaximumPasswordAge') { should be <= 30 }
#   end
#   describe security_policy do
#     its('MaximumPasswordAge') { should be > 0 }
#   end
# end

# # Password Policy: Minimum password age

# control 'Security_103' do
#   describe security_policy do
#     its('MinimumPasswordAge') { should be >= 1 }
#   end
# end

# # Password Policy: Minimum password length

# control 'Security_104' do
#   describe security_policy do
#     its('MinimumPasswordLength') { should be >= 14 }
#   end
# end

# # Password Policy: Password must meet complexity requirements

# control 'Security_105' do
#   describe security_policy do
#     its('PasswordComplexity') { should eq 1 }
#   end
# end

# # Password Policy: Store passwords using reversible encryption

# control 'Security_106' do
#   describe security_policy do
#     its('ClearTextPassword') { should eq 0 }
#   end
# end
