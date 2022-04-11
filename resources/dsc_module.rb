# To learn more about Custom Resources, see https://docs.chef.io/custom_resources.html
resource_name :dsc_module

provides :dsc_module

unified_mode true

property :module_name, String, name_property: true
property :dsc_resource, String, required: false, default: ''

default_action :import

action :import do
  # new_resource.dsc_resource.empty? ? (resource_name = new_resource.module_name) : (resource_name = new_resource.dsc_resource)

  cookbook_file "#{Chef::Config[:file_cache_path]}\\SecurityPolicyDSC.zip" do
    source 'dsc_modules/SecurityPolicyDSC.zip'
    not_if { ::Dir.exist?("C:\\Program\ Files\\WindowsPowerShell\\Modules\\SecurityPolicyDSC") }
  end

  archive_file new_resource.module_name do
    path "#{Chef::Config[:file_cache_path]}\\SecurityPolicyDSC.zip"
    destination "C:\\Program\ Files\\WindowsPowerShell\\Modules\\SecurityPolicyDSC"
    action :extract
    not_if { ::Dir.exist?("C:\\Program\ Files\\WindowsPowerShell\\Modules\\SecurityPolicyDSC") }
  end

  powershell_script 'Import SecurityPolicyDSC' do
    code <<-EOH
    Import-Module 'C:\\Program\ Files\\WindowsPowerShell\\Modules\\SecurityPolicyDSC\\SecurityPolicyDSC\\SecurityPolicyDsc.psd1'
    EOH
    # not_if '$mod=Get-Module -Name SecurityPolicyDSC; if ($mod -eq $null) { return $true } else { return $false }'
  end
end

action :remove do
  powershell_script 'Remove SecurityPolicyDSC' do
    code <<-EOH
    Remove-Module 'C:\\Program\ Files\\WindowsPowerShell\\Modules\\SecurityPolicyDSC\\SecurityPolicyDSC\\SecurityPolicyDsc.psd1'
    EOH
    # only_if '$mod=Get-Module -Name SecurityPolicyDSC; if ($mod -eq $null) { return $true } else { return $false }'
  end
end
