# Chef InSpec test for recipe wintel-2019::user_rights

# The Chef InSpec reference, with examples and extensive documentation, can be
# found at https://docs.chef.io/inspec/resources/

# Take ownership of files or other objects

# Obtain an impersonation token for another user in the same session

control 'User_Rights_Assignment_37' do
  describe security_policy do
    its('SeDelegateSessionUserImpersonatePrivilege') { should cmp nil }
  end
end

###################

control 'User_Rights_Assignment_46' do
  describe security_policy do
    its('SeTakeOwnershipPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# Shut down the system

control 'User_Rights_Assignment_44' do
  describe security_policy do
    its('SeShutdownPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# Restore files and directories

control 'User_Rights_Assignment_43' do
  describe security_policy do
    its('SeRestorePrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# Replace a process level token

control 'User_Rights_Assignment_42' do
  permitted_principals = ['S-1-5-19', 'S-1-5-20']
  describe security_policy.SeAssignPrimaryTokenPrivilege do
    it { should match_array permitted_principals }
  end
end

# Synchronize directory service data

control 'User_Rights_Assignment_45' do
  describe security_policy do
    its('SeSyncAgentPrivilege') { should be_empty }
  end
end

# Remove computer from docking station

control 'User_Rights_Assignment_41' do
  describe security_policy do
    its('SeUndockPrivilege') { should be_empty }
  end
end

# Profile system performance

control 'User_Rights_Assignment_40' do
  describe security_policy do
    its('SeSystemProfilePrivilege') { should be_empty }
  end
end

# Profile single process

control 'User_Rights_Assignment_39' do
  describe security_policy do
    its('SeProfileSingleProcessPrivilege') { should be_empty }
  end
end

# Performance volume maitainance tasks

control 'User_Rights_Assignment_38' do
  describe security_policy do
    its('SeManageVolumePrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# Modify firmware environment values

control 'User_Rights_Assignment_36' do
  describe security_policy do
    its('SeSystemEnvironmentPrivilege') { should be_empty }
  end
end

# Modify an object label

control 'User_Rights_Assignment_35' do
  describe security_policy do
    its('SeRelabelPrivilege') { should be_empty }
  end
end

# Manage auditing and security log

control 'User_Rights_Assignment_34' do
  describe security_policy do
    its('SeSecurityPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# Log on as a service

control 'User_Rights_Assignment_33' do
  describe security_policy do
    its('SeServiceLogonRight') { should match_array ['S-1-5-32-544'] }
  end
end

# Log on as a batch job

control 'User_Rights_Assignment_32' do
  describe security_policy do
    its('SeBatchLogonRight') { should match_array ['S-1-5-32-544'] }
  end
end

# Lock pages in memory

control 'User_Rights_Assignment_31' do
  describe security_policy do
    its('SeLockMemoryPrivilege') { should be_empty }
  end
end

# Load and unload device drivers

control 'User_Rights_Assignment_30' do
  describe security_policy do
    its('SeLoadDriverPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# Increase scheduling priority

control 'User_Rights_Assignment_29' do
  describe security_policy do
    its('SeIncreaseBasePriorityPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# Increase a process working set

control 'User_Rights_Assignment_28' do
  permitted_principals = ['S-1-5-32-544', 'S-1-5-19']
  describe security_policy.SeIncreaseWorkingSetPrivilege do
    it { should match_array permitted_principals }
  end
end

# Impersonate a client after authentication

control 'User_Rights_Assignment_27' do
  permitted_principals = ['S-1-5-32-544', 'S-1-5-19', 'S-1-5-20', 'S-1-5-6']
  describe security_policy.SeImpersonatePrivilege do
    it { should match_array permitted_principals }
  end
end

# Generate security audits

control 'User_Rights_Assignment_26' do
  permitted_principals = ['S-1-5-20', 'S-1-5-19']
  describe security_policy.SeAuditPrivilege do
    it { should match_array permitted_principals }
  end
end

# Force shutdown from a remote system

control 'User_Rights_Assignment_25' do
  describe security_policy do
    its('SeRemoteShutdownPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# Enable computer and user accounts to be trusted for delegation

control 'User_Rights_Assignment_24' do
  describe security_policy do
    its('SeEnableDelegationPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# Deny log on through Remote Desktop Services

control 'User_Rights_Assignment_23' do
  describe security_policy do
    its('SeDenyRemoteInteractiveLogonRight') { should match_array ['S-1-5-32-546'] }
  end
end

# Deny log on locally

control 'User_Rights_Assignment_22' do
  describe security_policy do
    its('SeDenyInteractiveLogonRight') { should match_array ['S-1-5-32-546'] }
  end
end

# Deny log on as a service

control 'User_Rights_Assignment_21' do
  describe security_policy do
    its('SeDenyServiceLogonRight') { should match_array ['S-1-5-32-546'] }
  end
end

# Deny log on as a batch job

control 'User_Rights_Assignment_20' do
  describe security_policy do
    its('SeDenyBatchLogonRight') { should match_array ['S-1-5-32-546'] }
  end
end

# Deny access to this computer from the network

control 'User_Rights_Assignment_19' do
  permitted_principals = ['S-1-5-32-546', 'S-1-5-7']
  describe security_policy.SeDenyNetworkLogonRight do
    it { should match_array permitted_principals }
  end
end

# Debug programs

control 'User_Rights_Assignment_18' do
  describe security_policy do
    its('SeDebugPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# Create symbolic links

control 'User_Rights_Assignment_17' do
  describe security_policy do
    its('SeCreateSymbolicLinkPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# Create permanent shared objects

control 'User_Rights_Assignment_16' do
  describe security_policy do
    its('SeCreatePermanentPrivilege') { should be_empty }
  end
end

# Create a token object

control 'User_Rights_Assignment_14' do
  describe security_policy do
    its('SeCreateTokenPrivilege') { should be_empty }
  end
end

# Create a pagefile

control 'User_Rights_Assignment_13' do
  describe security_policy do
    its('SeCreatePagefilePrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# Change the time zone

control 'User_Rights_Assignment_12' do
  permitted_principals = ['S-1-5-19', 'S-1-5-32-544']
  describe security_policy.SeTimeZonePrivilege do
    it { should match_array permitted_principals }
  end
end

# Change the system time

control 'User_Rights_Assignment_11' do
  permitted_principals = ['S-1-5-19', 'S-1-5-32-544']
  describe security_policy.SeSystemtimePrivilege do
    it { should match_array permitted_principals }
  end
end

# Bypass traverse checking

control 'User_Rights_Assignment_10' do
  permitted_principals = ['S-1-5-19', 'S-1-5-32-544', 'S-1-1-0', 'S-1-5-11', 'S-1-5-20']
  describe security_policy.SeChangeNotifyPrivilege do
    it { should match_array permitted_principals }
  end
end

# Back up files and directories

control 'User_Rights_Assignment_09' do
  permitted_principals = ['S-1-5-32-551', 'S-1-5-32-544']
  describe security_policy.SeBackupPrivilege do
    it { should match_array permitted_principals }
  end
end

# Allow log on through Remote Desktop Services

control 'User_Rights_Assignment_08' do
  describe security_policy do
    its('SeRemoteInteractiveLogonRight') { should be_empty }
  end
end

# Allow log on locally

control 'User_Rights_Assignment_07' do
  describe security_policy do
    its('SeInteractiveLogonRight') { should match_array ['S-1-5-32-544'] }
  end
end

# Adjust memory quotas for a process

control 'User_Rights_Assignment_06' do
  permitted_principals = ['S-1-5-19', 'S-1-5-20', 'S-1-5-32-544']
  describe security_policy.SeIncreaseQuotaPrivilege do
    it { should match_array permitted_principals }
  end
end

# Add workstations to domain

control 'User_Rights_Assignment_05' do
  describe security_policy do
    its('SeMachineAccountPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# Act as part of the operating system

control 'User_Rights_Assignment_04' do
  describe security_policy do
    its('SeTcbPrivilege') { should be_empty }
  end
end

# Access this computer from the network

control 'User_Rights_Assignment_03' do
  permitted_principals = ['S-1-5-11', 'S-1-5-9', 'S-1-5-32-544']
  describe security_policy.SeNetworkLogonRight do
    it { should match_array permitted_principals }
  end
end

# Access Credential Manager as a trusted caller

control 'User_Rights_Assignment_02' do
  describe security_policy do
    its('SeTrustedCredManAccessPrivilege') { should be_empty }
  end
end
