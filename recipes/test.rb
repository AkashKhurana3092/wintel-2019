# User rights

# 14 #
# windows_user_privilege 'Create global objects' do
#   privilege      'SeCreateGlobalPrivilege'
#   action         :clear
# end

#####################

# Security

# Audit: Audit the use of Backup and Restore privilege

# registry_key node['windows']['Policy']['FullPrivilegeAuditing'] do
#   values [{
#     name: 'FullPrivilegeAuditing',
#     type: :binary,
#     data: 0,
#   }]
#   recursive true
#   action :create
# end
