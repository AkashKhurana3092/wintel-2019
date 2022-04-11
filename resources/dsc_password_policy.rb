# To learn more about Custom Resources, see https://docs.chef.io/custom_resources.html
resource_name :dsc_password_policy

provides :dsc_password_policy
unified_mode true

password_policy_opts = %w(Enforce_password_history Maximum_Password_Age Minimum_Password_Age Minimum_Password_Length Password_must_meet_complexity_requirements Store_passwords_using_reversible_encryption)

property :id, String, name_property: true, equal_to: password_policy_opts
property :passopt, String, required: false, equal_to: password_policy_opts
property :passvalue, [String, Integer], required: true

default_action :set

action :set do
  new_resource.passopt.empty? ? (pass_option = new_resource.id) : (pass_option = new_resource.passopt)

  dsc_resource "Set \"#{pass_option}\" password policy option to #{new_resource.passvalue}" do
    module_name 'SecurityPolicyDsc'
    resource :AccountPolicy
    property :Name, 'PasswordPolicies'
    property :"#{pass_option}", new_resource.passvalue
  end
end
