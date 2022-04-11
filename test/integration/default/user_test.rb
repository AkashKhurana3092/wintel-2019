# Chef InSpec test for recipe wintel-2019::user

# The Chef InSpec reference, with examples and extensive documentation, can be
# found at https://docs.chef.io/inspec/resources/

# Prevent access to the about:flags page in Microsoft Edge

control 'User_01' do
  describe registry_key 'HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\MicrosoftEdge\\Main' do
    its('PreventAccessToAboutFlagsInMicrosoftEdge') { should eq 1 }
  end
end

# Do not allow Windows Messenger to be run

control 'User_02' do
  describe registry_key 'HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Messenger\\Client' do
    its('PreventRun') { should eq 0 }
  end
end

# Do not automatically start Windows Messenger initially

control 'User_03' do
  describe registry_key 'HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Messenger\\Client' do
    its('PreventAutoRun') { should eq 0 }
  end
end
