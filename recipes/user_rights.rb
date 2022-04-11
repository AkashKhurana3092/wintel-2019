
# Cookbook:: wintel-2019
# Recipe:: user_rights

# Copyright:: 2022, The Authors, All Rights Reserved.

# 46 user rights
windows_user_privilege 'Take ownership of files' do
  privilege      'SeTakeOwnershipPrivilege'
  users          ['BUILTIN\Administrators']
  action         :set
end

# 44
windows_user_privilege 'Shut down the system' do
  privilege      'SeShutdownPrivilege'
  users          ['BUILTIN\Administrators']
  action         :set
end

# 43
windows_user_privilege 'Restore files and directories' do
  privilege      'SeRestorePrivilege'
  users          ['BUILTIN\Administrators']
  action         :set
end

# 42
windows_user_privilege 'Replaces process level token' do
  privilege      'SeAssignPrimaryTokenPrivilege'
  users          ['NT AUTHORITY\Network Service', 'NT AUTHORITY\Local Service']
  action         :set
end

# 41 Need to delete it
# windows_user_privilege 'Replaces process level token' do
#   privilege      'SeAssignPrimaryTokenPrivilege'
#   users          ['NT AUTHORITY\Network Service', 'NT AUTHORITY\Local Service']
#   action         :set
# end

# 37
windows_user_privilege 'Performance volume maitainance tasks' do
  privilege      'SeManageVolumePrivilege'
  users          ['BUILTIN\Administrators']
  action         :set
end

# 33
if node['kernel']['cs_info']['part_of_domain'] == true
  windows_user_privilege 'Manage auditing and security log' do
    privilege      'SeSecurityPrivilege'
    users          ['BUILTIN\Administrators', 'BOS_AMERICA\VaronisAdmin']
    action         :set
  end
else
  windows_user_privilege 'Manage auditing and security log' do
    privilege      'SeSecurityPrivilege'
    users          ['BUILTIN\Administrators']
    action         :set
  end
end

# 32 # Need to be Fixed the privilage value
windows_user_privilege 'Log on as service' do
  privilege      'SeServiceLogonRight'
  users          ['BUILTIN\Administrators']
  action         :set
end

# 31
windows_user_privilege 'Log on as batch' do
  privilege      'SeBatchLogonRight'
  users          ['BUILTIN\Administrators']
  action         :set
end

# 29
windows_user_privilege 'Load and unload devices drivers' do
  privilege      'SeLoadDriverPrivilege'
  users          ['BUILTIN\Administrators']
  action         :set
end

# 28
windows_user_privilege 'increse schedulling priority' do
  privilege      'SeIncreaseBasePriorityPrivilege'
  users          ['BUILTIN\Administrators']
  action         :set
end

# 27
windows_user_privilege 'increase a process working set' do
  privilege      'SeIncreaseWorkingSetPrivilege'
  users          ['NT AUTHORITY\Local Service', 'BUILTIN\Administrators']
  action         :set
end

# 26
windows_user_privilege 'impersonate a client' do
  privilege      'SeImpersonatePrivilege'
  users          ['NT AUTHORITY\Service', 'NT AUTHORITY\Network Service', 'NT AUTHORITY\Local Service', 'BUILTIN\Administrators']
  action         :set
end

# 25
windows_user_privilege 'generate security audit' do
  privilege      'SeAuditPrivilege'
  users          ['NT AUTHORITY\Network Service', 'NT AUTHORITY\Local Service']
  action         :set
end

# 24
windows_user_privilege 'Force shutdown from a remote system' do
  privilege      'SeRemoteShutdownPrivilege'
  users          ['BUILTIN\Administrators']
  action         :set
end

# 23
windows_user_privilege 'Enable computer and user accounts to be trusted for delegation' do
  privilege      'SeEnableDelegationPrivilege'
  users          ['BUILTIN\Administrators']
  action         :set
end

# 22
windows_user_privilege 'Deny log on through Remote Desktop Services' do
  privilege      'SeDenyRemoteInteractiveLogonRight'
  users          ['BUILTIN\Guests']
  action         :set
end

# 20
windows_user_privilege 'Deny log on as a service' do
  privilege      'SeDenyServiceLogonRight'
  users          ['BUILTIN\Guests']
  action         :set
end

# 19
windows_user_privilege 'Deny log on as a batch job' do
  privilege      'SeDenyBatchLogonRight'
  users          ['BUILTIN\Guests']
  action         :set
end

# 18
windows_user_privilege 'Deny access to computer from the computer' do
  privilege      'SeDenyNetworkLogonRight'
  users          ['BUILTIN\Guests', 'NT AUTHORITY\ANONYMOUS LOGON']
  action         :set
end

# 17
windows_user_privilege 'Debug programs' do
  privilege      'SeDebugPrivilege'
  users          ['BUILTIN\Administrators']
  action         :set
end

# 12
windows_user_privilege 'Create a pagefile' do
  privilege      'SeCreatePagefilePrivilege'
  users          ['BUILTIN\Administrators']
  action         :set
end

# 11
windows_user_privilege 'Change the time zone' do
  privilege      'SeTimeZonePrivilege'
  users          ['NT AUTHORITY\Local Service', 'BUILTIN\Administrators']
  action         :set
end

# 10
windows_user_privilege 'Change the system time' do
  privilege      'SeSystemtimePrivilege'
  users          ['NT AUTHORITY\Local Service', 'BUILTIN\Administrators']
  action         :set
end

# 8
windows_user_privilege 'Back up files and directories' do
  privilege      'SeBackupPrivilege'
  users          ['BUILTIN\Administrators', 'BUILTIN\Backup Operators']
  action         :set
end

# 6
windows_user_privilege 'Allow log on locally' do
  privilege      'SeInteractiveLogonRight'
  users          ['BUILTIN\Administrators']
  action         :set
end

# 5
windows_user_privilege 'Adjust memory quotas for a process' do
  privilege      'SeIncreaseQuotaPrivilege'
  users          ['NT AUTHORITY\Network Service', 'NT AUTHORITY\Local Service', 'BUILTIN\Administrators']
  action         :set
end

# 4
windows_user_privilege 'Add workstations to domain' do
  privilege      'SeMachineAccountPrivilege'
  users          ['BUILTIN\Administrators']
  action         :set
end

# 2
windows_user_privilege 'Access this computer from the network' do
  privilege      'SeNetworkLogonRight'
  users          ['NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS', 'NT AUTHORITY\Authenticated Users', 'BUILTIN\Administrators']
  action         :set
end

# 9
windows_user_privilege 'Bypass traverse checking' do
  privilege      'SeChangeNotifyPrivilege'
  users          ['NT AUTHORITY\Network Service', 'NT AUTHORITY\Local Service', 'BUILTIN\Administrators', 'NT AUTHORITY\Authenticated Users', 'NT AUTHORITY\Everyone']
  action         :set
end

# 16 ####
windows_user_privilege 'Create symbolic links' do
  privilege      'SeCreateSymbolicLinkPrivilege'
  users          ['BUILTIN\Administrators'] # , 'NT Virtual Machine\Virtual Machines']
  action         :set
end

# 21 ####
if node['kernel']['cs_info']['part_of_domain'] == true
  windows_user_privilege 'Deny log on locally' do
    privilege      'SeDenyInteractiveLogonRight'
    users          ['BUILTIN\Guests', 'BOS_AMERICA\SUPPORT_388945a0', 'BOS_AMERICA\NotInUse', 'BOS_AMERICA\GG_Mandatory_Vacation', 'BOS_AMERICA\GG_Deny log on locally']
    action         :set
  end
else
  windows_user_privilege 'Deny log on locally' do
    privilege      'SeDenyInteractiveLogonRight'
    users          ['BUILTIN\Guests']
    action         :set
  end
end

####################### CLEAR RESOURCES ####################

# 45
windows_user_privilege 'Synchronize directory service data' do
  privilege      'SeSyncAgentPrivilege'
  action         :clear
end

# 40 #
windows_user_privilege 'Remove computer from docking station' do
  privilege      'SeUndockPrivilege'
  action         :clear
end

# 39 #
windows_user_privilege 'Profile system performance' do
  privilege      'SeSystemProfilePrivilege'
  action         :clear
end

# 38 #
windows_user_privilege 'Profile single process' do
  privilege      'SeProfileSingleProcessPrivilege'
  action         :clear
end

# 35 #
windows_user_privilege 'Modify firmware environment' do
  privilege      'SeSystemEnvironmentPrivilege'
  action         :clear
end

# 34
windows_user_privilege 'Modify object label' do
  privilege      'SeRelabelPrivilege'
  action         :clear
end

# 30
windows_user_privilege 'Lock pages in memory' do
  privilege      'SeLockMemoryPrivilege'
  action         :clear
end

# 15
windows_user_privilege 'Create permanent shared objects' do
  privilege      'SeCreatePermanentPrivilege'
  action         :clear
end

# 13
windows_user_privilege 'Create a token object' do
  privilege      'SeCreateTokenPrivilege'
  action         :clear
end

# 7 #
windows_user_privilege 'Allow log on through Remote Desktop Services' do
  privilege      'SeRemoteInteractiveLogonRight'
  action         :clear
end

# 3
windows_user_privilege 'Act as part of the operating system' do
  privilege      'SeTcbPrivilege'
  action         :clear
end

# 1
windows_user_privilege 'Access Credential Manager as a trusted caller' do
  privilege      'SeTrustedCredManAccessPrivilege'
  action         :clear
end

# 36 #
windows_user_privilege 'Obtain impersonation token' do
  privilege      'SeDelegateSessionUserImpersonatePrivilege'
  action         :clear
end
