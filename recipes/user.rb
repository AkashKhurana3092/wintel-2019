#
# Cookbook:: wintel-2019
# Recipe:: user
#
# Copyright:: 2022, The Authors, All Rights Reserved.

# Prevent access to the about:flags page in Microsoft Edge

registry_key node['windows']['Policy']['Edge'] do
  values [{
    name: 'PreventAccessToAboutFlagsInMicrosoftEdge',
    type: :dword,
    data: 1,
  }]
  recursive true
  action :create
end

# Do not allow Windows Messenger to be run

registry_key node['windows']['Policy']['Messenger'] do
  values [{
    name: 'PreventRun',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end

# Do not automatically start Windows Messenger initially

registry_key node['windows']['Policy']['Messenger'] do
  values [{
    name: 'PreventAutoRun',
    type: :dword,
    data: 0,
  }]
  recursive true
  action :create
end
