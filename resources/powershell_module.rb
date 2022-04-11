resource_name :powershell_module
provides :powershell_module
unified_mode true
property :mod_name, String, name_property: true

default_action :install

action :install do
  directory "c:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\#{new_resource.mod_name}"
  template "c:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\#{new_resource.mod_name}\\#{new_resource.mod_name}.psm1" do
    source "modules/#{new_resource.mod_name}.psm1.erb"
    sensitive true
    not_if "(Get-InstalledModule -Name #{new_resource.mod_name}).Installed"
  end
  powershell_script "load #{new_resource.mod_name} Module" do
    code <<-EOH
      Import-Module  #{new_resource.mod_name}
    EOH
    not_if "(Get-InstalledModule -Name #{new_resource.mod_name}).Installed"
    sensitive true
  end
end
