provides :windows_user_privilege
resource_name :windows_user_privilege

unified_mode true

PRIVILEGE_OPTS = %w( SeAssignPrimaryTokenPrivilege
                    SeAuditPrivilege
                    SeBackupPrivilege
                    SeBatchLogonRight
                    SeChangeNotifyPrivilege
                    SeCreateGlobalPrivilege
                    SeCreatePagefilePrivilege
                    SeCreatePermanentPrivilege
                    SeCreateSymbolicLinkPrivilege
                    SeCreateTokenPrivilege
                    SeDebugPrivilege
                    SeDenyBatchLogonRight
                    SeDenyInteractiveLogonRight
                    SeDenyNetworkLogonRight
                    SeDenyRemoteInteractiveLogonRight
                    SeDenyServiceLogonRight
                    SeEnableDelegationPrivilege
                    SeImpersonatePrivilege
                    SeIncreaseBasePriorityPrivilege
                    SeIncreaseQuotaPrivilege
                    SeIncreaseWorkingSetPrivilege
                    SeInteractiveLogonRight
                    SeLoadDriverPrivilege
                    SeLockMemoryPrivilege
                    SeMachineAccountPrivilege
                    SeManageVolumePrivilege
                    SeNetworkLogonRight
                    SeProfileSingleProcessPrivilege
                    SeRelabelPrivilege
                    SeRemoteInteractiveLogonRight
                    SeRemoteShutdownPrivilege
                    SeRestorePrivilege
                    SeSecurityPrivilege
                    SeServiceLogonRight
                    SeShutdownPrivilege
                    SeSyncAgentPrivilege
                    SeSystemEnvironmentPrivilege
                    SeSystemProfilePrivilege
                    SeSystemtimePrivilege
                    SeTakeOwnershipPrivilege
                    SeTcbPrivilege
                    SeTimeZonePrivilege
                    SeTrustedCredManAccessPrivilege
                    SeDelegateSessionUserImpersonatePrivilege
                    SeUndockPrivilege
                    ).freeze

property :principal, String,
description: 'An optional property to add the user to the given privilege. Use only with add and remove action.',
name_property: true

property :users, [Array, String],
description: 'An optional property to set the privilege for given users. Use only with set action.',
coerce: proc { |v| Array(v) }

property :privilege, [Array, String],
description: 'One or more privileges to set for users.',
required: true,
coerce: proc { |v| Array(v) },
callbacks: {
    "Privilege property restricted to the following values: #{PRIVILEGE_OPTS}" => ->(n) { (n - PRIVILEGE_OPTS).empty? },
}, identity: true

load_current_value do |new_resource|
  if new_resource.principal && (new_resource.action.include?(:add) || new_resource.action.include?(:remove))
    privilege Chef::ReservedNames::Win32::Security.get_account_right(new_resource.principal)
  end
end

action :add, description: 'Add a user privilege.' do
  ([*new_resource.privilege] - [*current_resource.privilege]).each do |user_right|
    converge_by("adding user '#{new_resource.principal}' privilege #{user_right}") do
      Chef::ReservedNames::Win32::Security.add_account_right(new_resource.principal, user_right)
    end
  end
end

action :set, description: 'Set the privileges that are listed in the `privilege` property for only the users listed in the `users` property.' do
  if new_resource.users.nil? || new_resource.users.empty?
    raise Chef::Exceptions::ValidationFailed, 'Users are required property with set action.'
  end

  users = []

  # Getting users with its domain for comparison
  new_resource.users.each do |user|
    user = Chef::ReservedNames::Win32::Security.lookup_account_name(user)
    users << user[1].account_name if user
  end

  new_resource.privilege.each do |privilege|
    accounts = Chef::ReservedNames::Win32::Security.get_account_with_user_rights(privilege)

    # comparing the existing accounts for privilege with users
    next if users == accounts
    # Removing only accounts which is not matching with users in new_resource
    (accounts - users).each do |account|
      converge_by("removing user '#{account}' from privilege #{privilege}") do
        Chef::ReservedNames::Win32::Security.remove_account_right(account, privilege)
      end
    end

    # Adding only users which is not already exist
    (users - accounts).each do |user|
      converge_by("adding user '#{user}' to privilege #{privilege}") do
        Chef::ReservedNames::Win32::Security.add_account_right(user, privilege)
      end
    end
  end
end

action :clear, description: 'Clear all user privileges' do
  new_resource.privilege.each do |privilege|
    accounts = Chef::ReservedNames::Win32::Security.get_account_with_user_rights(privilege)

    # comparing the existing accounts for privilege with users
    # Removing only accounts which is not matching with users in new_resource
    accounts.each do |account|
      converge_by("removing user '#{account}' from privilege #{privilege}") do
        Chef::ReservedNames::Win32::Security.remove_account_right(account, privilege)
      end
    end
  end
end

action :remove, description: 'Remove a user privilege' do
  curr_res_privilege = current_resource.privilege
  missing_res_privileges = (new_resource.privilege - curr_res_privilege)

  if missing_res_privileges
    Chef::Log.info("User \'#{new_resource.principal}\' for Privilege: #{missing_res_privileges.join(', ')} not found. Nothing to remove.")
  end

  (new_resource.privilege - missing_res_privileges).each do |user_right|
    converge_by("removing user #{new_resource.principal} from privilege #{user_right}") do
      Chef::ReservedNames::Win32::Security.remove_account_right(new_resource.principal, user_right)
    end
  end
end
