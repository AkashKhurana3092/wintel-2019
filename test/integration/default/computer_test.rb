# Chef InSpec test for recipe wintel-2019::computer

# The Chef InSpec reference, with examples and extensive documentation, can be
# found at https://docs.chef.io/inspec/resources/

control 'xccdf_org.cisecurity.benchmarks_rule_18.1.3_L2_Ensure_Allow_Online_Tips_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'AllowOnlineTips' }
    its('AllowOnlineTips') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.1.1.1_L1_Ensure_Prevent_enabling_lock_screen_camera_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization') do
    it { should have_property 'NoLockScreenCamera' }
    its('NoLockScreenCamera') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.1.1.2_L1_Ensure_Prevent_enabling_lock_screen_slide_show_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization') do
    it { should have_property 'NoLockScreenSlideshow' }
    its('NoLockScreenSlideshow') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.1.2.2_L1_Ensure_Allow_users_to_enable_online_speech_recognition_services_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\InputPersonalization') do
    it { should have_property 'AllowInputPersonalization' }
    its('AllowInputPersonalization') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.2.2_L1_Ensure_Do_not_allow_password_expiration_time_longer_than_required_by_policy_is_set_to_Enabled_MS_only' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd') do
    it { should have_property 'PwdExpirationProtectionEnabled' }
    its('PwdExpirationProtectionEnabled') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.2.3_L1_Ensure_Enable_Local_Admin_Password_Management_is_set_to_Enabled_MS_only' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft Services\\AdmPwd') do
    it { should have_property 'AdmPwdEnabled' }
    its('AdmPwdEnabled') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.3.1_L1_Ensure_Apply_UAC_restrictions_to_local_accounts_on_network_logons_is_set_to_Enabled_MS_only' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'LocalAccountTokenFilterPolicy' }
    its('LocalAccountTokenFilterPolicy') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.3.2_L1_Ensure_Configure_SMB_v1_client_driver_is_set_to_Enabled_Disable_driver_recommended' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.3.3_L1_Ensure_Configure_SMB_v1_server_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters') do
    it { should have_property 'SMB1' }
    its('SMB1') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.3.4_L1_Ensure_Enable_Structured_Exception_Handling_Overwrite_Protection_SEHOP_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel') do
    it { should have_property 'DisableExceptionChainValidation' }
    its('DisableExceptionChainValidation') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.3.5_L1_Ensure_Extended_Protection_for_LDAP_Authentication_Domain_Controllers_only_is_set_to_Enabled_Enabled_always_recommended_DC_Only' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters') do
    it { should have_property 'LdapEnforceChannelBinding' }
    its('LdapEnforceChannelBinding') { should cmp == 2 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.6.2_L1_Ensure_WDigest_Authentication_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest') do
    it { should have_property 'UseLogonCredential' }
    its('UseLogonCredential') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.4.1_L1_Ensure_MSS_AutoAdminLogon_Enable_Automatic_Logon_not_recommended_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should have_property 'AutoAdminLogon' }
    its('AutoAdminLogon') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should_not have_property 'DefaultPassword' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.4.2_L1_Ensure_MSS_DisableIPSourceRouting_IPv6_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters') do
    it { should have_property 'DisableIPSourceRouting' }
    its('DisableIPSourceRouting') { should cmp == 2 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.4.3_L1_Ensure_MSS_DisableIPSourceRouting_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should have_property 'DisableIPSourceRouting' }
    its('DisableIPSourceRouting') { should cmp == 2 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.3.4_L2_Ensure_MSS_DisableSavePassword_Prevent_the_dial-up_password_from_being_saved_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\RasMan\\Parameters') do
    it { should have_property 'disablesavepassword' }
    its('disablesavepassword') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.4.4_L1_Ensure_MSS_EnableICMPRedirect_Allow_ICMP_redirects_to_override_OSPF_generated_routes_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should have_property 'EnableICMPRedirect' }
    its('EnableICMPRedirect') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.4.5_L2_Ensure_MSS_KeepAliveTime_How_often_keep-alive_packets_are_sent_in_milliseconds_is_set_to_Enabled_300000_or_5_minutes_recommended' do
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should have_property 'KeepAliveTime' }
    its('KeepAliveTime') { should cmp == 300000 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.4.6_L1_Ensure_MSS_NoNameReleaseOnDemand_Allow_the_computer_to_ignore_NetBIOS_name_release_requests_except_from_WINS_servers_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NetBT\\Parameters') do
    it { should have_property 'nonamereleaseondemand' }
    its('nonamereleaseondemand') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.4.7_L2_Ensure_MSS_PerformRouterDiscovery_Allow_IRDP_to_detect_and_configure_Default_Gateway_addresses_could_lead_to_DoS_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should have_property 'PerformRouterDiscovery' }
    its('PerformRouterDiscovery') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.4.8_L1_Ensure_MSS_SafeDllSearchMode_Enable_Safe_DLL_search_mode_recommended_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager') do
    it { should have_property 'SafeDllSearchMode' }
    its('SafeDllSearchMode') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.4.9_L1_Ensure_MSS_ScreenSaverGracePeriod_The_time_in_seconds_before_the_screen_saver_grace_period_expires_0_recommended_is_set_to_Enabled_5_or_fewer_seconds' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should have_property 'ScreenSaverGracePeriod' }
    its('ScreenSaverGracePeriod') { should cmp <= 5 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.4.10_L2_Ensure_MSS_TcpMaxDataRetransmissions_IPv6_How_many_times_unacknowledged_data_is_retransmitted_is_set_to_Enabled_3' do
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\TCPIP6\\Parameters') do
    it { should have_property 'tcpmaxdataretransmissions' }
    its('tcpmaxdataretransmissions') { should cmp == 3 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.4.11_L2_Ensure_MSS_TcpMaxDataRetransmissions_How_many_times_unacknowledged_data_is_retransmitted_is_set_to_Enabled_3' do
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should have_property 'tcpmaxdataretransmissions' }
    its('tcpmaxdataretransmissions') { should cmp == 3 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.4.12_L1_Ensure_MSS_WarningLevel_Percentage_threshold_for_the_security_event_log_at_which_the_system_will_generate_a_warning_is_set_to_Enabled_90_or_less' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security') do
    it { should have_property 'WarningLevel' }
    its('WarningLevel') { should cmp <= 80 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.5.4.1_L1_Ensure_Turn_off_multicast_name_resolution_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient') do
    it { should have_property 'EnableMulticast' }
    its('EnableMulticast') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.5.5.1_L2_Ensure_Enable_Font_Providers_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'EnableFontProviders' }
    its('EnableFontProviders') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.5.8.1_L1_Ensure_Enable_insecure_guest_logons_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation') do
    it { should have_property 'AllowInsecureGuestAuth' }
    its('AllowInsecureGuestAuth') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.5.9.1_L2_Ensure_Turn_on_Mapper_IO_LLTDIO_driver_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'AllowLLTDIOOndomain' }
    its('AllowLLTDIOOndomain') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'ProhibitLLTDIOOnPrivateNet' }
    its('ProhibitLLTDIOOnPrivateNet') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'EnableLLTDIO' }
    its('EnableLLTDIO') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'AllowLLTDIOOnPublicNet' }
    its('AllowLLTDIOOnPublicNet') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.5.9.2_L2_Ensure_Turn_on_Responder_RSPNDR_driver_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'AllowRspndrOndomain' }
    its('AllowRspndrOndomain') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'ProhibitRspndrOnPrivateNet' }
    its('ProhibitRspndrOnPrivateNet') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'EnableRspndr' }
    its('EnableRspndr') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'AllowRspndrOnPublicNet' }
    its('AllowRspndrOnPublicNet') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.5.10.2_L2_Ensure_Turn_off_Microsoft_Peer-to-Peer_Networking_Services_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Peernet') do
    it { should have_property 'Disabled' }
    its('Disabled') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.5.11.2_L1_Ensure_Prohibit_installation_and_configuration_of_Network_Bridge_on_your_DNS_domain_network_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections') do
    it { should have_property 'NC_AllowNetBridge_NLA' }
    its('NC_AllowNetBridge_NLA') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.5.11.3_L1_Ensure_Prohibit_use_of_Internet_Connection_Sharing_on_your_DNS_domain_network_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections') do
    it { should have_property 'NC_ShowSharedAccessUI' }
    its('NC_ShowSharedAccessUI') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.5.11.4_L1_Ensure_Require_domain_users_to_elevate_when_setting_a_networks_location_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Network Connections') do
    it { should have_property 'NC_StdDomainUserSetLocation' }
    its('NC_StdDomainUserSetLocation') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.5.14.1_L1_Ensure_Hardened_UNC_Paths_is_set_to_Enabled_with_Require_Mutual_Authentication_and_Require_Integrity_set_for_all_NETLOGON_and_SYSVOL_shares' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths') do
    it { should have_property '\\*\NETLOGON' }
    its('\\*\NETLOGON') { should match(/[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1.*[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1/) }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths') do
    it { should have_property '\\*\SYSVOL' }
    its('\\*\SYSVOL') { should match(/[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1.*[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.5.20.1_L2_Ensure_Configuration_of_wireless_settings_using_Windows_Connect_Now_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should have_property 'EnableRegistrars' }
    its('EnableRegistrars') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.5.20.2_L2_Ensure_Prohibit_access_of_the_Windows_Connect_Now_wizards_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\UI') do
    it { should have_property 'DisableWcnUi' }
    its('DisableWcnUi') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.5.21.1_L1_Ensure_Minimize_the_number_of_simultaneous_connections_to_the_Internet_or_a_Windows_Domain_is_set_to_Enabled_3__Prevent_Wi-Fi_when_on_Ethernet' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy') do
    it { should have_property 'fMinimizeConnections' }
    its('fMinimizeConnections') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.5.21.2_L2_Ensure_Prohibit_connection_to_non-domain_networks_when_connected_to_domain_authenticated_network_is_set_to_Enabled_MS_only' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy') do
    it { should have_property 'fBlockNonDomain' }
    its('fBlockNonDomain') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.4.22.2.1_L1_Ensure_Allow_Windows_to_automatically_connect_to_suggested_open_hotspots_to_networks_shared_by_contacts_and_to_hotspots_offering_paid_services_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config') do
    it { should have_property 'AutoConnectAllowedOEM' }
    its('AutoConnectAllowedOEM') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.7.1.1_L2_Ensure_Turn_off_notifications_network_usage_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications') do
    it { should have_property 'NoCloudApplicationNotification' }
    its('NoCloudApplicationNotification') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.3.1_L1_Ensure_Include_command_line_in_process_creation_events_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit') do
    it { should have_property 'ProcessCreationIncludeCmdLine_Enabled' }
    its('ProcessCreationIncludeCmdLine_Enabled') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.4.1_L1_Ensure_Encryption_Oracle_Remediation_is_set_to_Enabled_Force_Updated_Clients' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\CredSSP\\Parameters') do
    it { should have_property 'AllowEncryptionOracle' }
    its('AllowEncryptionOracle') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.4.2_L1_Ensure_Remote_host_allows_delegation_of_non-exportable_credentials_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation') do
    it { should have_property 'AllowProtectedCreds' }
    its('AllowProtectedCreds') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.5.3_NG_Ensure_Turn_On_Virtualization_Based_Security_Virtualization_Based_Protection_of_Code_Integrity_is_set_to_Enabled_with_UEFI_lock' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard') do
    it { should have_property 'EnableVirtualizationBasedSecurity' }
    its('EnableVirtualizationBasedSecurity') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard') do
    it { should have_property 'HypervisorEnforcedCodeIntegrity' }
    its('HypervisorEnforcedCodeIntegrity') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.6.2_L1_Ensure_Allow_remote_access_to_the_Plug_and_Play_interface_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings') do
    it { should have_property 'AllowRemoteRPC' }
    its('AllowRemoteRPC') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.2.3.1.3_Set_Turn_off_Windows_Update_device_driver_searching_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DriverSearching') do
    it { should have_property 'DontPromptForWindowsUpdate' }
    its('DontPromptForWindowsUpdate') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.14.1_L1_Ensure_Boot-Start_Driver_Initialization_Policy_is_set_to_Enabled_Good_unknown_and_bad_but_critical' do
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\EarlyLaunch') do
    it { should have_property 'DriverLoadPolicy' }
    its('DriverLoadPolicy') { should cmp == 3 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.21.2_L1_Ensure_Configure_registry_policy_processing_Do_not_apply_during_periodic_background_processing_is_set_to_Enabled_FALSE' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') do
    it { should have_property 'NoGPOListChanges' }
    its('NoGPOListChanges') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') do
    it { should have_property 'NoBackgroundPolicy' }
    its('NoBackgroundPolicy') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.21.4_L1_Ensure_Continue_experiences_on_this_device_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'EnableCdp' }
    its('EnableCdp') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.21.5_L1_Ensure_Turn_off_background_refresh_of_Group_Policy_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('DisableBkGndGroupPolicy') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.19.1.1_L2_Ensure_Turn_off_access_to_the_Store_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer') do
    it { should have_property 'NoUseStoreOpenWith' }
    its('NoUseStoreOpenWith') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.1_L1_Ensure_Turn_off_downloading_of_print_drivers_over_HTTP_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Printers') do
    it { should have_property 'DisableWebPnPDownload' }
    its('DisableWebPnPDownload') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.2_L2_Ensure_Turn_off_handwriting_personalization_data_sharing_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\TabletPC') do
    it { should have_property 'PreventHandwritingDataSharing' }
    its('PreventHandwritingDataSharing') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.3_L2_Ensure_Turn_off_handwriting_recognition_error_reporting_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\HandwritingErrorReports') do
    it { should have_property 'PreventHandwritingErrorReports' }
    its('PreventHandwritingErrorReports') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.4_L2_Ensure_Turn_off_Internet_Connection_Wizard_if_URL_connection_is_referring_to_Microsoft.com_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Internet Connection Wizard') do
    it { should have_property 'ExitOnMSICW' }
    its('ExitOnMSICW') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.5_L1_Ensure_Turn_off_Internet_download_for_Web_publishing_and_online_ordering_wizards_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'NoWebServices' }
    its('NoWebServices') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.6_L2_Ensure_Turn_off_printing_over_HTTP_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Printers') do
    it { should have_property 'DisableHTTPPrinting' }
    its('DisableHTTPPrinting') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.7_L2_Ensure_Turn_off_Registration_if_URL_connection_is_referring_to_Microsoft.com_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Registration Wizard Control') do
    it { should have_property 'NoRegistration' }
    its('NoRegistration') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.8_L2_Ensure_Turn_off_Search_Companion_content_file_updates_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\SearchCompanion') do
    it { should have_property 'DisableContentFileUpdates' }
    its('DisableContentFileUpdates') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.9_L2_Ensure_Turn_off_the_Order_Prints_picture_task_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'NoOnlinePrintsWizard' }
    its('NoOnlinePrintsWizard') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.10_L2_Ensure_Turn_off_the_Publish_to_Web_task_for_files_and_folders_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'NoPublishingWizard' }
    its('NoPublishingWizard') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.11_L2_Ensure_Turn_off_the_Windows_Messenger_Customer_Experience_Improvement_Program_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Messenger\\Client') do
    it { should have_property 'CEIP' }
    its('CEIP') { should cmp == 2 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.12_L2_Ensure_Turn_off_Windows_Customer_Experience_Improvement_Program_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\SQMClient\\Windows') do
    it { should have_property 'CEIPEnable' }
    its('CEIPEnable') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.13_L2_Ensure_Turn_off_Windows_Error_Reporting_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Windows Error Reporting') do
    it { should have_property 'Disabled' }
    its('Disabled') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\PCHealth\\ErrorReporting') do
    it { should have_property 'DoReport' }
    its('DoReport') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.25.1_L2_Ensure_Support_device_authentication_using_certificate_is_set_to_Enabled_Automatic' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\kerberos\\parameters') do
    it { should have_property 'DevicePKInitBehavior' }
    its('DevicePKInitBehavior') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\kerberos\\parameters') do
    it { should have_property 'DevicePKInitEnabled' }
    its('DevicePKInitEnabled') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.26.1_L1_Ensure_Enumeration_policy_for_external_devices_incompatible_with_Kernel_DMA_Protection_is_set_to_Enabled_Block_All' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Kernel DMA Protection') do
    it { should have_property 'DeviceEnumerationPolicy' }
    its('DeviceEnumerationPolicy') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.27.1_L2_Ensure_Disallow_copying_of_user_input_methods_to_the_system_account_for_sign-in_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Control Panel\\International') do
    it { should have_property 'BlockUserInputMethodsForSignIn' }
    its('BlockUserInputMethodsForSignIn') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.28.1_L1_Ensure_Block_user_from_showing_account_details_on_sign-in_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'BlockUserFromShowingAccountDetailsOnSignin' }
    its('BlockUserFromShowingAccountDetailsOnSignin') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.28.2_L1_Ensure_Do_not_display_network_selection_UI_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'DontDisplayNetworkSelectionUI' }
    its('DontDisplayNetworkSelectionUI') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.28.3_L1_Ensure_Do_not_enumerate_connected_users_on_domain-joined_computers_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'DontEnumerateConnectedUsers' }
    its('DontEnumerateConnectedUsers') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.28.4_L1_Ensure_Enumerate_local_users_on_domain-joined_computers_is_set_to_Disabled_MS_only' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'EnumerateLocalUsers' }
    its('EnumerateLocalUsers') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.28.5_L1_Ensure_Turn_off_app_notifications_on_the_lock_screen_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'DisableLockScreenAppNotifications' }
    its('DisableLockScreenAppNotifications') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.28.6_L1_Ensure_Turn_off_picture_password_sign-in_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'BlockDomainPicturePassword' }
    its('BlockDomainPicturePassword') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.28.7_L1_Ensure_Turn_on_convenience_PIN_sign-in_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'AllowDomainPINLogon' }
    its('AllowDomainPINLogon') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.25.1_L1_Ensure_Untrusted_Font_Blocking_is_set_to_Enabled_Block_untrusted_fonts_and_log_events' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\MitigationOptions') do
    it { should have_property 'MitigationOptions_FontBocking' }
    its('MitigationOptions_FontBocking') { should eq '1000000000000' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.31.1_L2_Ensure_Allow_Clipboard_synchronization_across_devices_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'AllowCrossDeviceClipboard' }
    its('AllowCrossDeviceClipboard') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.31.2_L2_Ensure_Allow_upload_of_User_Activities_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'UploadUserActivities' }
    its('UploadUserActivities') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.34.6.1_L2_Ensure_Allow_network_connectivity_during_connected-standby_on_battery_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\f15576e8-98b7-4186-b944-eafa664402d9') do
    it { should have_property 'DCSettingIndex' }
    its('DCSettingIndex') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.34.6.2_L2_Ensure_Allow_network_connectivity_during_connected-standby_plugged_in_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\f15576e8-98b7-4186-b944-eafa664402d9') do
    it { should have_property 'ACSettingIndex' }
    its('ACSettingIndex') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.34.6.3_L1_Ensure_Require_a_password_when_a_computer_wakes_on_battery_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
    it { should have_property 'DCSettingIndex' }
    its('DCSettingIndex') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.34.6.4_L1_Ensure_Require_a_password_when_a_computer_wakes_plugged_in_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
    it { should have_property 'ACSettingIndex' }
    its('ACSettingIndex') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.36.1_L1_Ensure_Configure_Offer_Remote_Assistance_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fAllowUnsolicited' }
    its('fAllowUnsolicited') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.36.2_L1_Ensure_Configure_Solicited_Remote_Assistance_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fAllowToGetHelp' }
    its('fAllowToGetHelp') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.37.1_L1_Ensure_Enable_RPC_Endpoint_Mapper_Client_Authentication_is_set_to_Enabled_MS_only' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc') do
    it { should have_property 'EnableAuthEpResolution' }
    its('EnableAuthEpResolution') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.37.2_L2_Ensure_Restrict_Unauthenticated_RPC_clients_is_set_to_Enabled_Authenticated_MS_only' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc') do
    it { should have_property 'RestrictRemoteClients' }
    its('RestrictRemoteClients') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.47.5.1_L2_Ensure_Microsoft_Support_Diagnostic_Tool_Turn_on_MSDT_interactive_communication_with_support_provider_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\ScriptedDiagnosticsProvider\\Policy') do
    it { should have_property 'DisableQueryRemoteServer' }
    its('DisableQueryRemoteServer') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.47.11.1_L2_Ensure_EnableDisable_PerfTrack_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WDI\\{9c5a40da-b965-4fc3-8781-88dd50a6299d}') do
    it { should have_property 'ScenarioExecutionEnabled' }
    its('ScenarioExecutionEnabled') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.49.1_L2_Ensure_Turn_off_the_advertising_ID_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo') do
    it { should have_property 'DisabledByGroupPolicy' }
    its('DisabledByGroupPolicy') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.52.1.1_L2_Ensure_Enable_Windows_NTP_Client_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\W32Time\\TimeProviders\\NtpClient') do
    it { should have_property 'Enabled' }
    its('Enabled') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.8.52.1.2_L2_Ensure_Enable_Windows_NTP_Server_is_set_to_Disabled_MS_only' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\W32Time\\TimeProviders\\NtpServer') do
    it { should have_property 'Enabled' }
    its('Enabled') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.4.1_L2_Ensure_Allow_a_Windows_app_to_share_application_data_between_users_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StateManager') do
    it { should have_property 'AllowSharedLocalAppData' }
    its('AllowSharedLocalAppData') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.5.1_L2_Ensure_Let_Windows_apps__is_set_to_Enabled_Force_Deny' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy') do
    it { should have_property 'LetAppsAccessAccountInfo' }
    its('LetAppsAccessAccountInfo') { should cmp == 2 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy') do
    it { should have_property 'LetAppsAccessCalendar' }
    its('LetAppsAccessCalendar') { should cmp == 2 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy') do
    it { should have_property 'LetAppsAccessCallHistory' }
    its('LetAppsAccessCallHistory') { should cmp == 2 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy') do
    it { should have_property 'LetAppsAccessCamera' }
    its('LetAppsAccessCamera') { should cmp == 2 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy') do
    it { should have_property 'LetAppsAccessContacts' }
    its('LetAppsAccessContacts') { should cmp == 2 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy') do
    it { should have_property 'LetAppsAccessEmail' }
    its('LetAppsAccessEmail') { should cmp == 2 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy') do
    it { should have_property 'LetAppsAccessLocation' }
    its('LetAppsAccessLocation') { should cmp == 2 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy') do
    it { should have_property 'LetAppsAccessMessaging' }
    its('LetAppsAccessMessaging') { should cmp == 2 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy') do
    it { should have_property 'LetAppsAccessMicrophone' }
    its('LetAppsAccessMicrophone') { should cmp == 2 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy') do
    it { should have_property 'LetAppsAccessMotion' }
    its('LetAppsAccessMotion') { should cmp == 2 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy') do
    it { should have_property 'LetAppsAccessRadios' }
    its('LetAppsAccessRadios') { should cmp == 2 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy') do
    it { should have_property 'LetAppsAccessTrustedDevices' }
    its('LetAppsAccessTrustedDevices') { should cmp == 2 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy') do
    it { should have_property 'LetAppsSyncWithDevices' }
    its('LetAppsSyncWithDevices') { should cmp == 2 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.5.1_L2_Ensure_Let_Windows_apps__is_set_to_Enabled_Force_Deny' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy') do
    it { should have_property 'LetAppsAccessAccountInfo' }
    its('LetAppsAccessAccountInfo') { should cmp == 2 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.5.1_L2_Ensure_Let_Windows_apps__is_set_to_Enabled_Force_Deny' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy') do
    it { should have_property 'LetAppsAccessAccountInfo' }
    its('LetAppsAccessAccountInfo') { should cmp == 2 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.6.1_L1_Ensure_Allow_Microsoft_accounts_to_be_optional_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'MSAOptional' }
    its('MSAOptional') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.8.1_L1_Ensure_Disallow_Autoplay_for_non-volume_devices_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer') do
    it { should have_property 'NoAutoplayfornonVolume' }
    its('NoAutoplayfornonVolume') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.8.2_L1_Ensure_Set_the_default_behavior_for_AutoRun_is_set_to_Enabled_Do_not_execute_any_autorun_commands' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'NoAutorun' }
    its('NoAutorun') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.8.3_L1_Ensure_Turn_off_Autoplay_is_set_to_Enabled_All_drives' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'NoDriveTypeAutoRun' }
    its('NoDriveTypeAutoRun') { should cmp == 255 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.10.1.1_L1_Ensure_Configure_enhanced_anti-spoofing_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures') do
    it { should have_property 'EnhancedAntiSpoofing' }
    its('EnhancedAntiSpoofing') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.12.1_L2_Ensure_Allow_Use_of_Camera_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Camera') do
    it { should have_property 'AllowCamera' }
    its('AllowCamera') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.12.1_L1_Ensure_Turn_off_Microsoft_consumer_experiences_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent') do
    it { should have_property 'DisableWindowsConsumerFeatures' }
    its('DisableWindowsConsumerFeatures') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.14.1_L1_Ensure_Require_pin_for_pairing_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Connect') do
    it { should have_property 'RequirePinForPairing' }
    its('RequirePinForPairing') { should cmp == 2 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.13.1_L1_Ensure_Do_not_display_the_password_reveal_button_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\CredUI') do
    it { should have_property 'DisablePasswordReveal' }
    its('DisablePasswordReveal') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.13.2_L1_Ensure_Enumerate_administrator_accounts_on_elevation_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI') do
    it { should have_property 'EnumerateAdministrators' }
    its('EnumerateAdministrators') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.14.1_L1_Ensure_Allow_Telemetry_is_set_to_Enabled_0_-_Security_Enterprise_Only' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DataCollection') do
    it { should have_property 'AllowTelemetry' }
    its('AllowTelemetry') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.16.2_L2_Ensure_Configure_Authenticated_Proxy_usage_for_the_Connected_User_Experience_and_Telemetry_service_is_set_to_Enabled_Disable_Authenticated_Proxy_usage' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection') do
    it { should have_property 'DisableEnterpriseAuthProxy' }
    its('DisableEnterpriseAuthProxy') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.14.3_L1_Ensure_Do_not_show_feedback_notifications_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection') do
    it { should have_property 'DoNotShowFeedbackNotifications' }
    its('DoNotShowFeedbackNotifications') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.14.4_L1_Ensure_Toggle_user_control_over_Insider_builds_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds') do
    it { should have_property 'AllowBuildPreview' }
    its('AllowBuildPreview') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.24.1.1_L1_Ensure_Application_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application') do
    it { should have_property 'Retention' }
    its('Retention') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.24.1.2_L1_Ensure_Application_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application') do
    it { should have_property 'MaxSize' }
    its('MaxSize') { should cmp >= 32768 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.24.2.1_L1_Ensure_Security_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security') do
    it { should have_property 'Retention' }
    its('Retention') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.24.2.2_L1_Ensure_Security_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_196608_or_greater' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security') do
    it { should have_property 'MaxSize' }
    its('MaxSize') { should cmp >= 196608 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.24.1.1_L1_Ensure_Application_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application') do
    it { should have_property 'Retention' }
    its('Retention') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.24.3.2_L1_Ensure_Setup_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System') do
    it { should have_property 'MaxSize' }
    its('MaxSize') { should cmp >= 32768 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.80.1.1_L1_Ensure_Configure_Windows_Defender_SmartScreen_is_set_to_Enabled_Warn_and_prevent_bypass' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'EnableSmartScreen' }
    its('EnableSmartScreen') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'ShellSmartScreenLevel' }
    its('ShellSmartScreenLevel') { should eq 'Block' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.28.3_L1_Ensure_Turn_off_Data_Execution_Prevention_for_Explorer_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer') do
    it { should have_property 'NoDataExecutionPrevention' }
    its('NoDataExecutionPrevention') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.28.4_L1_Ensure_Turn_off_heap_termination_on_corruption_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer') do
    it { should have_property 'NoHeapTerminationOnCorruption' }
    its('NoHeapTerminationOnCorruption') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.28.5_L1_Ensure_Turn_off_shell_protocol_protected_mode_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'PreXPSP2ShellProtocolBehavior' }
    its('PreXPSP2ShellProtocolBehavior') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.31.1_L1_Ensure_Prevent_the_computer_from_joining_a_homegroup_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\HomeGroup') do
    it { should have_property 'DisableHomeGroup' }
    its('DisableHomeGroup') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.35.1_L2_Ensure_Turn_off_location_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors') do
    it { should have_property 'DisableLocation' }
    its('DisableLocation') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.39.1.1_L2_Ensure_Turn_off_Windows_Location_Provider_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors') do
    it { should have_property 'DisableWindowsLocationProvider' }
    its('DisableWindowsLocationProvider') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.43.1_L2_Ensure_Allow_Message_Service_Cloud_Sync_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Messaging') do
    it { should have_property 'AllowMessageSync' }
    its('AllowMessageSync') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.44.1_L1_Ensure_Block_all_consumer_Microsoft_account_user_authentication_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftAccount') do
    it { should have_property 'DisableUserAuth' }
    its('DisableUserAuth') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.43.1_L1_Ensure_Prevent_the_usage_of_OneDrive_for_file_storage_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\OneDrive') do
    it { should have_property 'DisableFileSyncNGSC' }
    its('DisableFileSyncNGSC') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.48.2.2_L1_Ensure_Do_not_allow_passwords_to_be_saved_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'DisablePasswordSaving' }
    its('DisablePasswordSaving') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.2.1_L2_Ensure_Allow_users_to_connect_remotely_by_using_Remote_Desktop_Services_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server') do
    it { should have_property 'fDenyTSConnections' }
    its('fDenyTSConnections') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.52.3.2.1_L2_Ensure_Restrict_Remote_Desktop_Services_users_to_a_single_Remote_Desktop_Services_session_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fSingleSessionPerUser' }
    its('fSingleSessionPerUser') { should eq 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.3.1_L2_Ensure_Do_not_allow_COM_port_redirection_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fDisableCcm' }
    its('fDisableCcm') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.3.2_L1_Ensure_Do_not_allow_drive_redirection_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fDisableCdm' }
    its('fDisableCdm') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.3.3_L2_Ensure_Do_not_allow_LPT_port_redirection_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fDisableLPT' }
    its('fDisableLPT') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.3.4_L2_Ensure_Do_not_allow_supported_Plug_and_Play_device_redirection_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fDisablePNPRedir' }
    its('fDisablePNPRedir') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.9.1_L1_Ensure_Always_prompt_for_password_upon_connection_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fPromptForPassword' }
    its('fPromptForPassword') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.9.2_L1_Ensure_Require_secure_RPC_communication_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fEncryptRPCTraffic' }
    its('fEncryptRPCTraffic') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.59.3.9.3_L1_Ensure_Require_use_of_specific_security_layer_for_remote_RDP_connections_is_set_to_Enabled_SSL' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'SecurityLayer' }
    its('SecurityLayer') { should cmp == 2 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.59.3.9.4_L1_Ensure_Require_user_authentication_for_remote_connections_by_using_Network_Level_Authentication_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'UserAuthentication' }
    its('UserAuthentication') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.9.3_L1_Ensure_Set_client_connection_encryption_level_is_set_to_Enabled_High_Level' do
  title "(L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'MinEncryptionLevel' }
    its('MinEncryptionLevel') { should cmp == 3 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.10.1_L2_Ensure_Set_time_limit_for_active_but_idle_Remote_Desktop_Services_sessions_is_set_to_Enabled_15_minutes_or_less' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'MaxIdleTime' }
    its('MaxIdleTime') { should cmp <= 900000 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'MaxIdleTime' }
    its('MaxIdleTime') { should cmp != 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.10.2_L2_Ensure_Set_time_limit_for_disconnected_sessions_is_set_to_Enabled_1_minute' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'MaxDisconnectionTime' }
    its('MaxDisconnectionTime') { should cmp == 7200000 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.11.1_L1_Ensure_Do_not_delete_temp_folders_upon_exit_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'DeleteTempDirsOnExit' }
    its('DeleteTempDirsOnExit') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.11.2_L1_Ensure_Do_not_use_temporary_folders_per_session_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'PerSessionTempDir' }
    its('PerSessionTempDir') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.49.1_L1_Ensure_Prevent_downloading_of_enclosures_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds') do
    it { should have_property 'DisableEnclosureDownload' }
    its('DisableEnclosureDownload') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.60.2_L2_Ensure_Allow_Cloud_Search_is_set_to_Enabled_Disable_Cloud_Search' do
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
      it { should have_property 'AllowCloudSearch' }
      its('AllowCloudSearch') { should cmp == 0 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
      it { should_not have_property 'AllowCloudSearch' }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.50.2_L1_Ensure_Allow_Cortana_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
    it { should have_property 'AllowCortana' }
    its('AllowCortana') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.54.3_L1_Ensure_Allow_Cortana_above_lock_screen_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
    it { should have_property 'AllowCortanaAboveLock' }
    its('AllowCortanaAboveLock') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.50.3_L1_Ensure_Allow_indexing_of_encrypted_files_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
    it { should have_property 'AllowIndexingEncryptedStoresOrItems' }
    its('AllowIndexingEncryptedStoresOrItems') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.50.4_L1_Ensure_Allow_search_and_Cortana_to_use_location_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
    it { should have_property 'AllowSearchToUseLocation' }
    its('AllowSearchToUseLocation') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.56.1_L2_Ensure_Turn_off_KMS_Client_Online_AVS_Validation_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Software Protection Platform') do
    it { should have_property 'NoGenTicket' }
    its('NoGenTicket') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.58.2_L1_Ensure_Turn_off_Automatic_Download_and_Install_of_updates_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore') do
    it { should have_property 'AutoDownload' }
    its('AutoDownload') { should cmp == 2 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.61.1_L1_Ensure_Turn_off_Automatic_Download_of_updates_on_Win8_machines_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore') do
    it { should exist }
    it { should have_property 'AutoDownload' }
    its('AutoDownload') { should eq 2 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.58.3_L1_Ensure_Turn_off_the_offer_to_update_to_the_latest_version_of_Windows_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore') do
    it { should have_property 'DisableOSUpgrade' }
    its('DisableOSUpgrade') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.58.4_L2_Ensure_Turn_off_the_Store_application_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore') do
    it { should have_property 'RemoveWindowsStore' }
    its('RemoveWindowsStore') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.77.14_L1_Ensure_Configure_detection_for_potentially_unwanted_applications_is_set_to_Enabled_Block' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender') do
    it { should have_property 'PUAProtection' }
    its('PUAProtection') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.76.14_L1_Ensure_Turn_off_Windows_Defender_AntiVirus_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender') do
    it { should have_property 'DisableAntiSpyware' }
    its('DisableAntiSpyware') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.76.3.1_L1_Ensure_Configure_local_setting_override_for_reporting_to_Microsoft_MAPS_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet') do
    it { should have_property 'LocalSettingOverrideSpynetReporting' }
    its('LocalSettingOverrideSpynetReporting') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.66.3.1_L2_Ensure_Join_Microsoft_MAPS_is_set_to_Disabled' do
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows Defender\\Spynet') do
      it { should have_property 'SpynetReporting' }
      its('SpynetReporting') { should cmp == 2 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows Defender\\Spynet') do
      it { should_not have_property 'SpynetReporting' }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.45.8.1_L1_Ensure_Scan_all_downloaded_files_and_attachments_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection') do
    it { should have_property 'DisableIOAVProtection' }
    its('DisableIOAVProtection') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.45.8.2_L1_Ensure_Turn_off_real-time_protection_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection') do
    it { should have_property 'DisableRealtimeMonitoring' }
    its('DisableRealtimeMonitoring') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.76.7.1_L1_Ensure_Turn_on_behavior_monitoring_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection') do
    it { should have_property 'DisableBehaviorMonitoring' }
    its('DisableBehaviorMonitoring') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.76.9.1_L2_Ensure_Configure_Watson_events_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting') do
    it { should have_property 'DisableGenericRePorts' }
    its('DisableGenericRePorts') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.76.10.1_L1_Ensure_Scan_removable_drives_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan') do
    it { should have_property 'DisableRemovableDriveScanning' }
    its('DisableRemovableDriveScanning') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.76.10.2_L1_Ensure_Turn_on_e-mail_scanning_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan') do
    it { should have_property 'DisableEmailScanning' }
    its('DisableEmailScanning') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.76.13.1.1_L1_Ensure_Configure_Attack_Surface_Reduction_rules_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR') do
    it { should have_property 'ExploitGuard_ASR_Rules' }
    its('ExploitGuard_ASR_Rules') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.76.13.1.2_L1_Ensure_Configure_Attack_Surface_Reduction_rules_Set_the_state_for_each_ASR_rule_is_configured' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' }
    its('75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property '3b576869-a4ec-4529-8536-b80a7769e899' }
    its('3b576869-a4ec-4529-8536-b80a7769e899') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property 'd4f940ab-401b-4efc-aadc-ad5f3c50688a' }
    its('d4f940ab-401b-4efc-aadc-ad5f3c50688a') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' }
    its('92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property '5beb7efe-fd9a-4556-801d-275e5ffc04cc' }
    its('5beb7efe-fd9a-4556-801d-275e5ffc04cc') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property 'd3e037e1-3eb8-44c8-a917-57927947596d' }
    its('d3e037e1-3eb8-44c8-a917-57927947596d') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' }
    its('be9ba2d9-53ea-4cdc-84e5-9b1eeee46550') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.76.13.3.1_L1_Ensure_Prevent_users_and_apps_from_accessing_dangerous_websites_is_set_to_Enabled_Block' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection') do
    it { should have_property 'EnableNetworkProtection' }
    its('EnableNetworkProtection') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.80.1.1_L1_Ensure_Configure_Windows_Defender_SmartScreen_is_set_to_Enabled_Warn_and_prevent_bypass' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'EnableSmartScreen' }
    its('EnableSmartScreen') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'ShellSmartScreenLevel' }
    its('ShellSmartScreenLevel') { should eq 'Block' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.73.1_L2_Ensure_Allow_suggested_apps_in_Windows_Ink_Workspace_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace') do
    it { should have_property 'AllowSuggestedAppsInWindowsInkWorkspace' }
    its('AllowSuggestedAppsInWindowsInkWorkspace') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.73.2_L1_Ensure_Allow_Windows_Ink_Workspace_is_set_to_Enabled_On_but_disallow_access_above_lock_OR_Disabled_but_not_Enabled_On' do
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace') do
      it { should have_property 'AllowWindowsInkWorkspace' }
      its('AllowWindowsInkWorkspace') { should cmp == 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace') do
      it { should have_property 'AllowWindowsInkWorkspace' }
      its('AllowWindowsInkWorkspace') { should cmp == 0 }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.69.1_L1_Ensure_Allow_user_control_over_installs_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'EnableUserControl' }
    its('EnableUserControl') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.69.2_L1_Ensure_Always_install_with_elevated_privileges_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'AlwaysInstallElevated' }
    its('AlwaysInstallElevated') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.69.3_L2_Ensure_Prevent_Internet_Explorer_security_prompt_for_Windows_Installer_scripts_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'SafeForScripting' }
    its('SafeForScripting') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.70.1_L1_Ensure_Sign-in_last_interactive_user_automatically_after_a_system-initiated_restart_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'DisableAutomaticRestartSignOn' }
    its('DisableAutomaticRestartSignOn') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.84.1_L1_Ensure_Turn_on_PowerShell_Script_Block_Logging_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging') do
    it { should have_property 'EnableScriptBlockLogging' }
    its('EnableScriptBlockLogging') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.84.2_L1_Ensure_Turn_on_PowerShell_Transcription_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription') do
    it { should have_property 'EnableTranscripting' }
    its('EnableTranscripting') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.81.1.1_L1_Ensure_Allow_Basic_authentication_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    it { should have_property 'AllowBasic' }
    its('AllowBasic') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.81.1.2_L1_Ensure_Allow_unencrypted_traffic_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    it { should have_property 'AllowUnencryptedTraffic' }
    its('AllowUnencryptedTraffic') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.81.1.3_L1_Ensure_Disallow_Digest_authentication_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    it { should have_property 'AllowDigest' }
    its('AllowDigest') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.81.2.1_L1_Ensure_Allow_Basic_authentication_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should have_property 'AllowBasic' }
    its('AllowBasic') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.86.2.2_L2_Ensure_Allow_remote_server_management_through_WinRM_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should exist }
    it { should have_property 'AllowAutoConfig' }
    its('AllowAutoConfig') { should eq 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.81.2.2_L1_Ensure_Allow_unencrypted_traffic_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should have_property 'AllowUnencryptedTraffic' }
    its('AllowUnencryptedTraffic') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.81.2.3_L1_Ensure_Disallow_WinRM_from_storing_RunAs_credentials_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should have_property 'DisableRunAs' }
    its('DisableRunAs') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.82.1_L2_Ensure_Allow_Remote_Shell_Access_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service\\WinRS') do
    it { should have_property 'AllowRemoteShellAccess' }
    its('AllowRemoteShellAccess') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.79.1.1_L1_Ensure_Prevent_users_from_modifying_settings_is_set_to_Enabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection') do
    it { should have_property 'DisallowExploitProtectionOverride' }
    its('DisallowExploitProtectionOverride') { should cmp == 1 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.16.5_L1_Ensure_Toggle_user_control_over_Insider_builds_is_set_to_Disabled' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds') do
    it { should have_property 'AllowBuildPreview' }
    its('AllowBuildPreview') { should cmp == 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_18.9.90.1.2_L1_Ensure_Select_when_Quality_Updates_are_received_is_set_to_Enabled_0_days' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    it { should have_property 'DeferQualityUpdates' }
    its('DeferQualityUpdates') { should cmp == 0 }
  end
end

control 'Force automatic setup for all users' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WorkFolders') do
    it { should have_property 'AutoProvision' }
    its('AutoProvision') { should cmp == 0 }
  end
end

control 'Select when Preview Builds and Feature Updates are receive' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    it { should have_property 'DeferFeatureUpdates' }
    its('DeferFeatureUpdates') { should cmp == 0 }
  end
end

control 'Hide the Virus and threat protection area' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Virus and threat protection') do
    it { should have_property 'UILockdown' }
    its('UILockdown') { should cmp == 1 }
  end
end

control 'Hide the Ransomware data recovery area' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Virus and threat protection') do
    it { should have_property 'HideRansomwareRecovery' }
    its('HideRansomwareRecovery') { should cmp == 1 }
  end
end

control 'Hide Windows Security Systray' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Systray') do
    it { should have_property 'HideSystray' }
    its('HideSystray') { should cmp == 1 }
  end
end

control 'Hide non-critical notification' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications') do
    it { should have_property 'DisableEnhancedNotifications' }
    its('DisableEnhancedNotifications') { should cmp == 1 }
  end
end

control 'Hide all notifications' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications') do
    it { should have_property 'DisableNotifications' }
    its('DisableNotifications') { should cmp == 1 }
  end
end

control 'Hide the Firewall and network protection area' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Firewall and network protection') do
    it { should have_property 'UILockdown' }
    its('UILockdown') { should cmp == 1 }
  end
end

control 'Hide the Family options area' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Family options') do
    it { should have_property 'UILockdown' }
    its('UILockdown') { should cmp == 1 }
  end
end

control 'Configure customized notifications' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Enterprise Customization') do
    it { should have_property 'EnableForToasts' }
    its('EnableForToasts') { should cmp == 0 }
  end
end

control 'Configure customized contact information' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Enterprise Customization') do
    it { should have_property 'EnableInApp' }
    its('EnableInApp') { should cmp == 0 }
  end
end

control 'Hide the TPM Firmware Update recommendation' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device security') do
    it { should have_property 'DisableTpmFirmwareUpdateWarning' }
    its('DisableTpmFirmwareUpdateWarning') { should cmp == 1 }
  end
end

control 'Hide the Security processor (TPM) troubleshooter page' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device security') do
    it { should have_property 'HideTPMTroubleshooting' }
    its('HideTPMTroubleshooting') { should cmp == 1 }
  end
end

control 'Hide the Secure boot area' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device security') do
    it { should have_property 'HideSecureBoot' }
    its('HideSecureBoot') { should cmp == 1 }
  end
end

control 'Hide the Device security are' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device security') do
    it { should have_property 'UILockdown' }
    its('UILockdown') { should cmp == 1 }
  end
end

control 'Disable the Clear TPM button' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device security') do
    it { should have_property 'DisableClearTpmButton' }
    its('DisableClearTpmButton') { should cmp == 1 }
  end
end

control 'Turn On Compatibility HTTPS Listene' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should have_property 'HttpsCompatibilityListener' }
    its('HttpsCompatibilityListener') { should cmp == 1 }
  end
end

control 'Turn On Compatibility HTTP Listener' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should have_property 'HttpCompatibilityListener' }
    its('HttpCompatibilityListener') { should cmp == 0 }
  end
end

control 'Turn on Script Execution' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell') do
    it { should have_property 'ExecutionPolicy' }
    its('ExecutionPolicy') { should cmp == 'RemoteSigned' }
  end
end

control 'Turn off Windows Mobility Center' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\MobilityCenter') do
    it { should have_property 'NoMobilityCenter' }
    its('NoMobilityCenter') { should cmp == 1 }
  end
end

control 'Do not automatically start Windows Messenger initially' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Messenger\\Client') do
    it { should have_property 'PreventAutoRun' }
    its('PreventAutoRun') { should cmp == 1 }
  end
end

control 'Do not allow Windows Messenger to be run' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Messenger\\Client') do
    it { should have_property 'PreventRun' }
    its('PreventRun') { should cmp == 1 }
  end
end

control 'Prevent Media Sharing' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsMediaPlayer') do
    it { should have_property 'PreventLibrarySharing' }
    its('PreventLibrarySharing') { should cmp == 1 }
  end
end

control 'Prevent Automatic Update' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsMediaPlayer') do
    it { should have_property 'DisableAutoUpdate' }
    its('DisableAutoUpdate') { should cmp == 1 }
  end
end

control 'Do Not Show First Use Dialog Boxe' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsMediaPlayer') do
    it { should have_property 'GroupPrivacyAcceptance' }
    its('GroupPrivacyAcceptance') { should cmp == 1 }
  end
end

control 'Prevent Windows Media DRM Internet Acces' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WMDRM') do
    it { should have_property 'DisableOnline' }
    its('DisableOnline') { should cmp == 1 }
  end
end

control 'Display information about previous logons during user logo' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'DisplayLastLogonInfo' }
    its('DisplayLastLogonInfo') { should cmp == 0 }
  end
end

control 'Disable or enable software Secure Attention Sequence' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'SoftwareSASGeneration' }
    its('SoftwareSASGeneration') { should cmp == 3 }
  end
end

control 'Turn off shared components' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'DisableSharedComponent' }
    its('DisableSharedComponent') { should cmp == 1 }
  end
end

control 'Turn off logging via package setting' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'DisableLoggingFromPackage' }
    its('DisableLoggingFromPackage') { should cmp == 0 }
  end
end

control 'Turn off creation of System Restore checkpoints' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'LimitSystemRestoreCheckpointing' }
    its('LimitSystemRestoreCheckpointing') { should cmp == 1 }
  end
end

control 'Remove browse dialog box for new source' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'DisableBrowse' }
    its('DisableBrowse') { should cmp == 1 }
  end
end

control 'Prohibit User Installs' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'DisableUserInstalls' }
    its('DisableUserInstalls') { should cmp == 1 }
  end
end

control 'Prohibit use of Restart Manage' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'DisableAutomaticApplicationShutdown' }
    its('DisableAutomaticApplicationShutdown') { should cmp == 1 }
  end
end

control 'Prohibit rollback' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'DisablePatchUninstall' }
    its('DisablePatchUninstall') { should cmp == 1 }
  end
end

control 'Prohibit removal of update' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'DisablePatchUninstall' }
    its('DisablePatchUninstall') { should cmp == 1 }
  end
end

control 'Prohibit non-administrators from applying vendor signed updates' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'DisableLUAPatching' }
    its('DisableLUAPatching') { should cmp == 1 }
  end
end

control 'Prevent users from using Windows Installer to install updates and upgrades' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'DisablePatch' }
    its('DisablePatch') { should cmp == 1 }
  end
end

control 'Allow users to use media source while elevate' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'AllowLockdownMedia' }
    its('AllowLockdownMedia') { should cmp == 0 }
  end
end

control 'Allow users to patch elevated products' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'AllowLockdownPatch' }
    its('AllowLockdownPatch') { should cmp == 0 }
  end
end

control 'Allow users to browse for source while elevated' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'AllowLockdownBrowse' }
    its('AllowLockdownBrowse') { should cmp == 0 }
  end
end

control 'Configure protected folders' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access') do
    it { should have_property 'ExploitGuard_ControlledFolderAccess_ProtectedFolders' }
    its('ExploitGuard_ControlledFolderAccess_ProtectedFolders') { should cmp == 1 }
  end
end

control 'Configure Controlled folder access' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access') do
    it { should have_property 'EnableControlledFolderAccess' }
    its('EnableControlledFolderAccess') { should cmp == 1 }
  end
end

control 'Turn on scan after signature update' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Microsoft Antimalware\\Signature Updates') do
    it { should have_property 'DisableScanOnUpdate' }
    its('DisableScanOnUpdate') { should cmp == 0 }
  end
end

control 'Specify the time to check for definition updates' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Microsoft Antimalware\\Signature Updates') do
    it { should have_property 'ScheduleTime' }
    its('ScheduleTime') { should cmp == 120 }
  end
end

control 'Specify the interval to check for definition updates' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Microsoft Antimalware\\Signature Updates') do
    it { should have_property 'SignatureUpdateInterval' }
    its('SignatureUpdateInterval') { should cmp == 3 }
  end
end

control 'Initiate definition update on startu' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Microsoft Antimalware\\Signature Updates') do
    it { should have_property 'DisableUpdateOnStartupWithoutEngine' }
    its('DisableUpdateOnStartupWithoutEngine') { should cmp == 0 }
  end
end

control 'Define the number of days before virus definitions are considered out of date' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Microsoft Antimalware\\Signature Updates') do
    it { should have_property 'AVSignatureDue' }
    it { should have_property 'ASSignatureDue' }
    it { should have_property 'SignatureUpdateCatchupInterval' }
    it { should have_property 'UpdateOnStartUp' }
    it { should have_property 'RealTimeSignatureDelivery' }
    it { should have_property 'SignatureDisableNotification' }
    it { should have_property 'DisableScheduledSignatureUpdateOnBattery' }
    it { should have_property 'ForceUpdateFromMU' }
    its('AVSignatureDue') { should cmp == 7 }
    its('ASSignatureDue') { should cmp == 7 }
    its('SignatureUpdateCatchupInterval') { should cmp == 1 }
    its('UpdateOnStartUp') { should cmp == 1 }
    its('RealTimeSignatureDelivery') { should cmp == 1 }
    its('SignatureDisableNotification') { should cmp == 0 }
    its('DisableScheduledSignatureUpdateOnBattery') { should cmp == 0 }
    its('ForceUpdateFromMU') { should cmp == 1 }
  end
end

control 'Turn on reparse point scanning' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan') do
    its('DisableReparsePointScanning') { should cmp == 1 }
    its('PurgeItemsAfterDelay') { should cmp == 30 }
    its('DisableHeuristics') { should cmp == 0 }
    its('DisableEmailScanning') { should cmp == 0 }
    its('DisableCatchupQuickScan') { should cmp == 0 }
    its('DisableCatchupFullScan') { should cmp == 0 }
    its('ScanOnlyIfIdle') { should cmp == 0 }
    its('ScheduleTime') { should cmp == 120 }
    its('ScheduleQuickScanTime') { should cmp == 120 }
    its('ScanParameters') { should cmp == 2 }
    its('AvgCPULoadFactor') { should cmp == 50 }
    its('DisableRemovableDriveScanning') { should cmp == 0 }
    its('DisablePackedExeScanning') { should cmp == 0 }
    its('DisableScanningNetworkFiles') { should cmp == 0 }
    its('DisableArchiveScanning') { should cmp == 0 }
    its('DisableScanningMappedNetworkDrivesForFullScan') { should cmp == 1 }
    its('DisableRestorePoint') { should cmp == 1 }
    its('LowCpuPriority') { should cmp == 0 }
    its('LocalSettingOverrideScanParameters') { should cmp == 0 }
    its('LocalSettingOverrideScheduleTime') { should cmp == 0 }
    its('LocalSettingOverrideScheduleQuickScanTime') { should cmp == 0 }
    its('LocalSettingOverrideScheduleDay') { should cmp == 0 }
    its('LocalSettingOverrideAvgCPULoadFactor') { should cmp == 1 }
    its('CheckForSignaturesBeforeRunningScan') { should cmp == 1 }
    its('AllowPause') { should cmp == 0 }
  end
end

control 'Turn off enhanced notifications' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting') do
    it { should have_property 'DisableEnhancedNotifications' }
    its('DisableEnhancedNotifications') { should cmp == 1 }
  end
end

control 'Configure local setting override for the time of day to run a scheduled full scan to complete remediation' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Remediation') do
    it { should have_property 'LocalSettingOverrideScan_ScheduleTime' }
    its('LocalSettingOverrideScan_ScheduleTime') { should cmp == 0 }
  end
end

control 'Monitor file and program activity on your compute' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection') do
    it { should have_property 'DisableRawWriteNotification' }
    it { should have_property 'DisableScanOnRealtimeEnable' }
    it { should have_property 'DisableOnAccessProtection' }
    its('DisableOnAccessProtection') { should cmp == 0 }
    its('DisableRawWriteNotification') { should cmp == 0 }
    its('DisableScanOnRealtimeEnable') { should cmp == 0 }
  end
end

control 'Turn on definition retirement' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\NIS\\Consumers\\IPS') do
    it { should have_property 'DisableSignatureRetirement' }
    its('DisableSignatureRetirement') { should cmp == 0 }
  end
end

control 'Configure extended cloud check' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine') do
    it { should have_property 'MpBafsExtendedTimeout' }
    it { should have_property 'MpCloudBlockLevel' }
    its('MpCloudBlockLevel') { should cmp == 2 }
    its('MpBafsExtendedTimeout') { should cmp == 50 }
  end
end

control 'Send file samples when further analysis is require' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet') do
    it { should have_property 'SubmitSamplesConsent' }
    it { should have_property 'DisableBlockAtFirstSeen' }
    its('DisableBlockAtFirstSeen') { should cmp == 0 }
    its('SubmitSamplesConsent') { should cmp == 1 }
  end
end

control 'Turn off Auto Exclusions' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions') do
    it { should have_property 'DisableAutoExclusions' }
    it { should have_property 'Exclusions_Processes' }
    it { should have_property 'Exclusions_Paths' }
    it { should have_property 'Exclusions_Extensions' }
    its('DisableAutoExclusions') { should cmp == 0 }
    its('Exclusions_Processes') { should cmp == 0 }
    its('Exclusions_Paths') { should cmp == 0 }
    its('Exclusions_Extensions') { should cmp == 0 }
  end
end

control 'Turn off routine remediation' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender') do
    it { should have_property 'DisableRoutinelyTakingAction' }
    it { should have_property 'DisableLocalAdminMerge' }
    it { should have_property 'AllowFastServiceStartup' }
    it { should have_property 'ServiceKeepAlive' }
    its('DisableRoutinelyTakingAction') { should cmp == 0 }
    its('ServiceKeepAlive') { should cmp == 0 }
    its('AllowFastServiceStartup') { should cmp == 1 }
    its('DisableLocalAdminMerge') { should cmp == 1 }
  end
end

control 'Allow Uninstallation of Language Features' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\TextInput') do
    it { should have_property 'AllowLanguageFeaturesUninstall' }
    its('AllowLanguageFeaturesUninstall') { should cmp == 0 }
  end
end

control 'Prohibit New Task Creation' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Task Scheduler5.0') do
    it { should have_property 'Task Deletion' }
    it { should have_property 'Task Creation' }
    it { should have_property 'DragAndDrop' }
    it { should have_property 'Allow Browse' }
    it { should have_property 'Execution' }
    it { should have_property 'Property Pages' }
    it { should have_property 'Disable Advanced' }
    its('Disable Advanced') { should cmp == 1 }
    its('Execution') { should cmp == 1 }
    its('Property Pages') { should cmp == 1 }
    its('Task Deletion') { should cmp == 1 }
    its('Task Creation') { should cmp == 1 }
    its('DragAndDrop') { should cmp == 1 }
    its('Allow Browse') { should cmp == 1 }
  end
end

control 'Only display the private store within the Microsoft Store' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore') do
    it { should have_property 'RequirePrivateStoreOnly' }
    its('RequirePrivateStoreOnly') { should cmp == 0 }
  end
end

control 'Disable all apps from Microsoft Stor' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore') do
    it { should have_property 'DisableStoreApps' }
    its('DisableStoreApps') { should cmp == 0 }
  end
end

control 'Allow use of diacritics' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
    it { should have_property 'AllowUsingDiacritics' }
    its('AllowUsingDiacritics') { should cmp == 0 }
  end
end

control 'Set time limit for logoff of RemoteApp sessions' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'RemoteAppLogoffTimeLimit' }
    its('RemoteAppLogoffTimeLimit') { should cmp == 7200000 }
  end
end

control 'Remove Windows Security item from Start men' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'NoNTSecurity' }
    its('NoNTSecurity') { should cmp == 1 }
  end
end

control 'Limit number of monitor' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    its('MaxMonitors') { should cmp == 2 }
    its('fNoFontSmoothing') { should cmp == 1 }
    its('fAllowDesktopCompositionOnServer') { should cmp == 0 }
    its('UseUniversalPrinterDriverFirst') { should cmp == 4 }
    its('fPolicyFallbackPrintDriver') { should cmp == 0 }
    its('RedirectOnlyDefaultClientPrinter') { should cmp == 0 }
    its('fForceClientLptDef') { should cmp == 0 }
    its('fDisableCpm') { should cmp == 1 }
    its('fDisableTerminalServerTooltip') { should cmp == 1 }
    its('fDisableCameraRedir') { should cmp == 1 }
    its('fDisablePNPRedir') { should cmp == 1 }
    its('fEnableSmartCard') { should cmp == 0 }
    its('fDisableLPT') { should cmp == 1 }
    its('fDisableCdm') { should cmp == 1 }
    its('fDisableCcm') { should cmp == 1 }
    its('fDisableClip') { should cmp == 1 }
    its('fEnableTimeZoneRedirection') { should cmp == 0 }
    its('fDisableAudioCapture') { should cmp == 1 }
    its('fDisableCam') { should cmp == 1 }
    its('fSingleSessionPerUser') { should cmp == 1 }
    its('SelectTransport') { should cmp == 1 }
    its('MaxInstanceCount') { should cmp == 2 }
    its('KeepAliveInterval') { should cmp == 120 }
    its('KeepAliveEnable') { should cmp == 1 }
    its('fDisableAutoReconnect') { should cmp == 1 }
    its('fDenyTSConnection') { should cmp == 0 }
    its('fAllowUnlistedRemotePrograms') { should cmp == 0 }
    its('TrustedCertThumbprints') { should cmp == 'Disabled' }
    its('PromptForCredsOnClient') { should cmp == 1 }
    its('AuthenticationLevel') { should cmp == 1 }
    its('AllowSignedFiles') { should cmp == 0 }
    its('AllowUnsignedFiles') { should cmp == 0 }
  end
end

control 'Turn off Windows Installer RDS Compatibility' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\TSAppSrv\\TSMSI') do
    its('Enable') { should cmp == 0 }
  end
end

control 'Turn Off UDP On Client' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\Client') do
    it { should have_property 'fClientDisableUDP' }
    its('fClientDisableUDP') { should cmp == 1 }
  end
end

control 'Do not allow hardware accelerated decoding' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\Client') do
    it { should have_property 'EnableHardwareMode' }
    its('EnableHardwareMode') { should cmp == 0 }
  end
end

control 'Save documents to OneDrive by default' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\OneDrive') do
    it { should have_property 'DisableLibrariesDefaultSaveToOneDrive' }
    its('DisableLibrariesDefaultSaveToOneDrive') { should cmp == 0 }
  end
end

control 'Force automatic setup for all users' do
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PreviewBuilds') do
    it { should have_property 'AllowBuildPreview' }
    its('AllowBuildPreview') { should cmp == 0 }
  end
end

control 'Disable remote Desktop Sharing' do
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Conferencing') do
    it { should have_property 'NoRDS' }
    its('NoRDS') { should cmp == 1 }
  end
end

# Block Flash activation in Office documents

control 'Computer_01' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Office\\Common\\COM Compatibility' do
    its('Comment') { should eq 'Block All Activation' }
  end
end

# LSA Protection

control 'Computer_02' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
    its('RunAsPPL') { should eq 00000001 }
  end
end

# Lsass.exe audit mode

control 'Computer_03' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\LSASS.exe' do
    its('AuditLevel') { should eq 8 }
  end
end

# Remove "Run As Different User" from context menus

control 'Computer_04' do
  describe registry_key 'HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\Explorer' do
    its('ShowRunAsDifferentUserInStart') { should eq 1 }
  end
end

# MSS: (AutoReboot) Allow Windows to automatically restart after a system crash

control 'Computer_05' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' do
    its('AutoReboot') { should eq 1 }
  end
end

# MSS: (AutoShareServer) Enable Administrative Shares

control 'Computer_06' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' do
    its('AutoShareServer') { should eq 0 }
  end
end

# MSS: (DisableSavePassword) Prevent the dial-up passsword from being

control 'Computer_07' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\RasMan\\Parameters' do
    its('DisableSavePassword') { should eq 1 }
  end
end

# MSS: (EnableDeadGWDetect) Allow automatic detection of dead network gateways

control 'Computer_08' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' do
    its('EnableDeadGWDetect') { should eq 0 }
  end
end

# MSS: (Hidden) Hide Computer From the Browse List (not recommended except for highly secure

control 'Computer_09' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' do
    its('Hidden') { should eq 0 }
  end
end

# MSS: (NtfsDisable8dot3NameCreation) Enable the computer to stop

control 'Computer_10' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\FileSystem' do
    its('NtfsDisable8dot3NameCreation') { should eq 1 }
  end
end

# Enable Hotspot Authentication

control 'Computer_11' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\HotspotAuthentication' do
    its('Enabled') { should eq 0 }
  end
end

# Route all traffic through the internal network

control 'Computer_12' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition' do
    its('ForceTunneling') { should eq 'Disabled' }
  end
end

# Allow or Disallow use of the Offline Files feature

control 'Computer_13' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetCache' do
    its('Enabled') { should eq 0 }
  end
end

# Network\Lanman Server - Cipher suite order

control 'Computer_14' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanServer' do
    its('CipherSuiteOrder') { should eq [''] }
  end
end

# Network\Lanman Server - Honor cipher suite order

control 'Computer_15' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanServer' do
    its('HonorCipherSuiteOrder') { should eq 1 }
  end
end

# Network\Lanman Workstation : Cipher suite order

control 'Computer_16' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation' do
    its('CipherSuiteOrder') { should eq [''] }
  end
end

# Settings Page Visibility

control 'Computer_17' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' do
    its('SettingsPageVisibility') { should eq 'showonly:about' }
  end
end

# ECC Curve Order

control 'Computer_18' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002' do
    its('EccCurves') { should eq [''] }
  end
end

# SSL Cipher Suite Order

control 'Computer_19' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002' do
    its('Functions') { should eq 'LS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' }
  end
end

# Set 6to4 Relay Name

control 'Computer_20' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\TCPIP\\v6Transition' do
    its('6to4_RouterName') { should eq '' }
  end
end

# Set 6to4 Relay Name Resolution Interval

control 'Computer_21' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\TCPIP\\v6Transition' do
    its('6to4_RouterNameResolutionInterval') { should eq '' }
  end
end

# Set 6to4 State

control 'Computer_22' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\TCPIP\\v6Transition' do
    its('6to4_State') { should eq 'Disabled' }
  end
end

# Set IP-HTTPS State

control 'Computer_23' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\IPHTTPS\\IPHTTPSInterface' do
    its('IPHTTPS_ClientUrl') { should eq '' }
  end
end

control 'Computer_24' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\IPHTTPS\\IPHTTPSInterface' do
    its('IPHTTPS_ClientState') { should eq 3 }
  end
end

# Set ISATAP Router Name

control 'Computer_25' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\TCPIP\\v6Transition' do
    its('ISATAP_RouterName') { should eq '' }
  end
end

# Set ISATAP State

control 'Computer_26' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\TCPIP\\v6Transition' do
    its('ISATAP_State') { should eq 'Disabled' }
  end
end

# Set Teredo Client Port

control 'Computer_27' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\TCPIP\\v6Transition' do
    its('Teredo_ClientPort') { should eq 0 }
  end
end

# Set Teredo Default Qualified

control 'Computer_28' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\TCPIP\\v6Transition' do
    its('Teredo_DefaultQualified') { should eq '' }
  end
end

# Set Teredo Refresh Rate

control 'Computer_29' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\TCPIP\\v6Transition' do
    its('Teredo_RefreshRate') { should eq 0 }
  end
end

# Set Teredo Server Name

control 'Computer_30' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\TCPIP\\v6Transition' do
    its('Teredo_ServerName') { should eq '' }
  end
end

# Set Teredo State

control 'Computer_31' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\TCPIP\\v6Transition' do
    its('Teredo_State') { should eq 'Disabled' }
  end
end

# Prohibit connection to roaming Mobile Broadband networks

control 'Computer_32' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy' do
    its('fBlockRoaming') { should eq 1 }
  end
end

# Let Windows apps access cellular data

control 'Computer_34' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WwanSvc\\CellularDataAccess' do
    its('LetAppsAccessCellularData') { should eq 2 }
  end
end

# Enable App-V Client

control 'Computer_35' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\AppV\\Client' do
    its('Enabled') { should eq 0 }
  end
end

# Do not send a Windows error report when a generic driver is installed on a device

control 'Computer_36' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings' do
    its('DisableSendGenericDriverNotFoundToWER') { should eq 1 }
  end
end

# Prevent creation of a system restore point during device activity that would normally prompt creation of a restore point

control 'Computer_37' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings' do
    its('DisableSystemRestore') { should eq 1 }
  end
end

# Prevent device metadata retrieval from the Internet

control 'Computer_38' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Device Metadata' do
    its('PreventDeviceMetadataFromNetwork') { should eq 1 }
  end
end

# Prevent Windows from sending an error report when a device driver requests additional software during installation

control 'Computer_39' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings' do
    its('DisableSendRequestAdditionalSoftwareToWER') { should eq 1 }
  end
end

# Turn off "Found New Hardware" balloons during device installation

control 'Computer_40' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings' do
    its('DisableBalloonTips') { should eq 1 }
  end
end

# Allow administrators to override Device Installation Restriction policies

control 'Computer_41' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions' do
    its('AllowAdminInstall') { should eq 0 }
  end
end

# Prevent installation of removable devices

control 'Computer_42' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions' do
    its('DenyRemovableDevices') { should eq 1 }
  end
end

# Apply policy to removable media

control 'Computer_43' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DiskQuota' do
    its('ApplyToRemovableMedia') { should eq 1 }
  end
end

# Allow non-administrators to install drivers for these device setup classes

control 'Computer_44' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DriverInstall\\Restrictions' do
    its('AllowUserDeviceClasses') { should eq 0 }
  end
end

# Prevent bypassing SmartScreen Filter warnings

control 'Computer_45' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter' do
    its('PreventOverrideAppRepUnknown') { should eq 1 }
  end
end

control 'Computer_46' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter' do
    its('PreventOverride') { should eq 1 }
  end
end

# Prevent managing SmartScreen Filter

control 'Computer_47' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter' do
    its('EnabledV9') { should eq 1 }
  end
end

# Prevent per-user installation of ActiveX controls

control 'Computer_48' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Security\ActiveX' do
    its('BlockNonAdminActiveXInstall') { should eq 1 }
  end
end

# Security Zones: Do not allow users to add/delete sites

control 'Computer_49' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' do
    its('Security_zones_map_edit') { should eq 1 }
  end
end

# Security Zones: Do not allow users to change policies

control 'Computer_50' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' do
    its('Security_options_edit') { should eq 1 }
  end
end

# Security Zones: Use only machine settings

control 'Computer_51' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' do
    its('Security_HKLM_only') { should eq 1 }
  end
end

# Specify use of ActiveX Installer Service for installation of ActiveX controls

control 'Computer_52' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AxInstaller' do
    its('OnlyUseAXISForActiveXInstall') { should eq 1 }
  end
end

# Turn off Crash Detection

control 'Computer_53' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Restrictions' do
    its('NoCrashDetection') { should eq 1 }
  end
end

# Turn off the Security Settings Check feature

control 'Computer_54' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Security' do
    its('DisableSecuritySettingsCheck') { should eq 0 }
  end
end

# Prevent ignoring certificate errors

control 'Computer_55' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' do
    its('PreventIgnoreCertErrors') { should eq 1 }
  end
end

# Allow software to run or install even if the signature is invalid

control 'Computer_56' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Download' do
    its('RunInvalidSignatures') { should eq 0 }
  end
end

# Check for server certificate revocation

control 'Computer_57' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' do
    its('CertificateRevocation') { should eq 1 }
  end
end

# Check for signatures on downloaded programs

control 'Computer_58' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Download' do
    its('CheckExeSignatures') { should eq 'yes' }
  end
end

# Do not allow ActiveX controls to run in Protected Mode when Enhanced Protected Mode is enabled

control 'Computer_59' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\Main' do
    its('DisableEPMCompat') { should eq 1 }
  end
end

# Turn off encryption support

control 'Computer_60' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' do
    its('SecureProtocols') { should eq 2048 }
  end
end

# Turn on 64-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows

control 'Computer_61' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\Main' do
    its('Isolation64Bit') { should eq 1 }
  end
end

# Turn on Enhanced Protected Mode

control 'Computer_62' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\Main' do
    its('Isolation') { should eq 'PMEM' }
  end
end

# Intranet Sites: Include all network paths (UNCs)

control 'Computer_63' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap' do
    its('UNCAsIntranet') { should eq 0 }
  end
end

# Turn on certificate address mismatch warning

control 'Computer_64' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' do
    its('WarnOnBadCertRecving') { should eq 1 }
  end
end

# Access data sources across domains

control 'Computer_65' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('1406') { should eq 3 }
  end
end

# Allow cut, copy or paste operations from the clipboard via script

control 'Computer_66' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('1407') { should eq 3 }
  end
end

# Allow drag and drop or copy and paste files

control 'Computer_67' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('1802') { should eq 3 }
  end
end

# Allow loading of XAML files

control 'Computer_68' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('2402') { should eq 3 }
  end
end

# Allow only approved domains to use ActiveX controls without prompt

control 'Computer_69' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('120b') { should eq 3 }
  end
end

# Allow only approved domains to use the TDC ActiveX control

control 'Computer_70' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('120c') { should eq 3 }
  end
end

# Allow scripting of Internet Explorer WebBrowser controls

control 'Computer_71' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('1206') { should eq 3 }
  end
end

# Allow script-initiated windows without size or position constraints

control 'Computer_72' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('2102') { should eq 3 }
  end
end

# Allow scriptlets

control 'Computer_73' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('1209') { should eq 3 }
  end
end

# Allow updates to status bar via script

control 'Computer_74' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('2103') { should eq 3 }
  end
end

# Allow VBScript to run in Internet Explorer

control 'Computer_75' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('140C') { should eq 3 }
  end
end

# Automatic prompting for file downloads

control 'Computer_76' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('2200') { should eq 3 }
  end
end

# Don't run antimalware programs against ActiveX controls

control 'Computer_77' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('270C') { should eq 0 }
  end
end

# Download signed ActiveX controls

control 'Computer_78' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('1001') { should eq 3 }
  end
end

# Download unsigned ActiveX controls

control 'Computer_79' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('1004') { should eq 3 }
  end
end

# Enable dragging of content from different domains across windows

control 'Computer_80' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('2709') { should eq 3 }
  end
end

# Enable dragging of content from different domains within a window

control 'Computer_81' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('2708') { should eq 3 }
  end
end

# Include local path when user is uploading files to a server

control 'Computer_82' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('160A') { should eq 3 }
  end
end

# Initialize and script ActiveX controls not marked as safe

control 'Computer_83' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('1201') { should eq 3 }
  end
end

# Java permissions

control 'Computer_84' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('1C00') { should eq 0 }
  end
end

# Launching applications and files in an IFRAME

control 'Computer_85' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('1804') { should eq 3 }
  end
end

# Logon options

control 'Computer_86' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('1A00') { should eq 65536 }
  end
end

# Navigate windows and frames across different domains

control 'Computer_87' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('1607') { should eq 3 }
  end
end

# Run .NET Framework-reliant components not signed with Authenticode

control 'Computer_88' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('2004') { should eq 3 }
  end
end

# Run .NET Framework-reliant components signed with Authenticode

control 'Computer_89' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('2001') { should eq 3 }
  end
end

# Show security warning for potentially unsafe files

control 'Computer_90' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('1806') { should eq 1 }
  end
end

# Turn on Cross-Site Scripting Filter

control 'Computer_91' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('1409') { should eq 0 }
  end
end

# Turn on Protected Mode

control 'Computer_92' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('2500') { should eq 0 }
  end
end

# Turn on SmartScreen Filter scan

control 'Computer_93' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('2301') { should eq 0 }
  end
end

# Use Pop-up Blocker

control 'Computer_94' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('1809') { should eq 0 }
  end
end

# Userdata persistence

control 'Computer_95' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('1606') { should eq 3 }
  end
end

# Web sites in less privileged Web content zones can navigate into this zone

control 'Computer_96' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
    its('2101') { should eq 3 }
  end
end

# Don't run antimalware programs against ActiveX controls

control 'Computer_97' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1' do
    its('270C') { should eq 0 }
  end
end

# Initialize and script ActiveX controls not marked as safe

control 'Computer_98' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1' do
    its('1201') { should eq 3 }
  end
end

# Java permissions

control 'Computer_99' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1' do
    its('1C00') { should eq 65536 }
  end
end

# Don't run antimalware programs against ActiveX controls

control 'Computer_100' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\0' do
    its('270C') { should eq 0 }
  end
end

# Java permissions

control 'Computer_101' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\0' do
    its('270C') { should eq 0 }
  end
end

# Turn on SmartScreen Filter scan

control 'Computer_102' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Lockdown_Zones\\3' do
    its('2301') { should eq 0 }
  end
end

# Java permissions

control 'Computer_103' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Lockdown_Zones\\1' do
    its('1C00') { should eq 0 }
  end
end

# Java permissions

control 'Computer_104' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Lockdown_Zones\\0' do
    its('1C00') { should eq 0 }
  end
end

# Java permissions

control 'Computer_105' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Lockdown_Zones\\4' do
    its('1C00') { should eq 0 }
  end
end

# Turn on SmartScreen Filter scan

control 'Computer_106' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Lockdown_Zones\\4' do
    its('2301') { should eq 0 }
  end
end

# Java permissions

control 'Computer_107' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Lockdown_Zones\\2' do
    its('1C00') { should eq 0 }
  end
end

# Access data sources across domains

control 'Computer_108' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1406') { should eq 3 }
  end
end

# Allow active scripting

control 'Computer_109' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1400') { should eq 3 }
  end
end

# Allow binary and script behaviors

control 'Computer_110' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('2000') { should eq 3 }
  end
end

# Allow cut, copy or paste operations from the clipboard via script

control 'Computer_111' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1407') { should eq 3 }
  end
end

# Allow drag and drop or copy and paste files

control 'Computer_112' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1802') { should eq 3 }
  end
end

# Allow file downloads

control 'Computer_113' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1803') { should eq 3 }
  end
end

# Allow loading of XAML files

control 'Computer_114' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('2402') { should eq 3 }
  end
end

# Allow META REFRESH

control 'Computer_115' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1608') { should eq 3 }
  end
end

# Allow only approved domains to use ActiveX controls without prompt

control 'Computer_116' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('120b') { should eq 3 }
  end
end

# Allow only approved domains to use the TDC ActiveX control

control 'Computer_117' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('120c') { should eq 3 }
  end
end

# Allow scripting of Internet Explorer WebBrowser controls

control 'Computer_118' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1206') { should eq 3 }
  end
end

# Allow script-initiated windows without size or position constraints

control 'Computer_119' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('2102') { should eq 3 }
  end
end

# Allow scriptlets

control 'Computer_120' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1209') { should eq 3 }
  end
end

# Allow updates to status bar via script

control 'Computer_121' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('2103') { should eq 3 }
  end
end

# Allow VBScript to run in Internet Explorer

control 'Computer_122' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('140C') { should eq 3 }
  end
end

# Automatic prompting for file downloads

control 'Computer_123' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('2200') { should eq 3 }
  end
end

# Don't run antimalware programs against ActiveX controls

control 'Computer_124' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('270C') { should eq 0 }
  end
end

# Download signed ActiveX controls

control 'Computer_125' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1001') { should eq 3 }
  end
end

# Download unsigned ActiveX controls

control 'Computer_126' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1004') { should eq 3 }
  end
end

# Enable dragging of content from different domains across windows

control 'Computer_127' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('2709') { should eq 3 }
  end
end

# Enable dragging of content from different domains within a window

control 'Computer_128' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('2708') { should eq 3 }
  end
end

# Include local path when user is uploading files to a server

control 'Computer_129' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('160A') { should eq 3 }
  end
end

# Initialize and script ActiveX controls not marked as safe

control 'Computer_130' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1201') { should eq 3 }
  end
end

# Java permissions

control 'Computer_131' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1C00') { should eq 0 }
  end
end

# Launching applications and files in an IFRAME

control 'Computer_132' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1804') { should eq 3 }
  end
end

# Logon options

control 'Computer_133' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1A00') { should eq 196608 }
  end
end

# Navigate windows and frames across different domains

control 'Computer_134' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1607') { should eq 3 }
  end
end

# Run .NET Framework-reliant components not signed with Authenticode

control 'Computer_135' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('2004') { should eq 3 }
  end
end

# Run .NET Framework-reliant components signed with Authenticode

control 'Computer_136' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('2001') { should eq 3 }
  end
end

# Run ActiveX controls and plugins

control 'Computer_137' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1200') { should eq 3 }
  end
end

# Script ActiveX controls marked safe for scripting

control 'Computer_138' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1405') { should eq 3 }
  end
end

# Scripting of Java applets

control 'Computer_139' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1402') { should eq 3 }
  end
end

# Show security warning for potentially unsafe files

control 'Computer_140' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1806') { should eq 3 }
  end
end

# Turn on Cross-Site Scripting Filter

control 'Computer_141' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1409') { should eq 0 }
  end
end

# Turn on Protected Mode

control 'Computer_142' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('2500') { should eq 0 }
  end
end

# Turn on SmartScreen Filter scan

control 'Computer_143' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('2301') { should eq 0 }
  end
end

# Use Pop-up Blocker

control 'Computer_144' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1809') { should eq 0 }
  end
end

# Userdata persistence

control 'Computer_145' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('1606') { should eq 3 }
  end
end

# Web sites in less privileged Web content zones can navigate into this zone

control 'Computer_146' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4' do
    its('2101') { should eq 3 }
  end
end

# Don't run antimalware programs against ActiveX controls

control 'Computer_147' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\2' do
    its('270C') { should eq 0 }
  end
end

# Initialize and script ActiveX controls not marked as safe

control 'Computer_148' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\2' do
    its('1201') { should eq 3 }
  end
end

# Java permissions

control 'Computer_149' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\2' do
    its('1C00') { should eq 65536 }
  end
end

# Allow fallback to SSL 3.0 (Internet Explorer)

control 'Computer_150' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' do
    its('EnableSSL3Fallback') { should eq 0 }
  end
end

# Remove "Run this time" button for outdated ActiveX controls in Internet Explorer

control 'Computer_151' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Ext' do
    its('RunThisTimeEnabled') { should eq 0 }
  end
end

# Turn off blocking of outdated ActiveX controls for Internet Explorer

control 'Computer_152' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Ext' do
    its('VersionCheckEnabled') { should eq 1 }
  end
end

# Windows Components\Internet Explorer\Security Features\Consistent Mime Handling - Internet Explorer Processes

control 'Computer_153' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_MIME_HANDLING' do
    its('Reserved') { should eq "1" }
  end
end

# Windows Components\Internet Explorer\Security Features\Mime Sniffing Safety Feature - Internet Explorer Processes

control 'Computer_154' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_MIME_SNIFFING' do
    its('Reserved') { should eq "1" }
  end
end

# Windows Components\Internet Explorer\Security Features\MK Protocol Security Restriction - Internet Explorer Processes

control 'Computer_155' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_DISABLE_MK_PROTOCOL' do
    its('Reserved') { should eq "1" }
  end
end

# Windows Components\Internet Explorer\Security Features\Notification bar - Internet Explorer Processes

control 'Computer_156' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_SECURITYBAND' do
    its('Reserved') { should eq "1" }
  end
end

# Windows Components\Internet Explorer\Security Features\Protection From Zone Elevation - Internet Explorer Processes

control 'Computer_157' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_ZONE_ELEVATION' do
    its('Reserved') { should eq "1" }
  end
end

# Windows Components\Internet Explorer\Security Features\Restrict ActiveX Install - Internet Explorer Processes

control 'Computer_158' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_RESTRICT_ACTIVEXINSTALL' do
    its('Reserved') { should eq "1" }
  end
end

# Windows Components\Internet Explorer\Security Features\Restrict File Download - Internet Explorer Processes

control 'Computer_159' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_RESTRICT_FILEDOWNLOAD' do
    its('Reserved') { should eq "1" }
  end
end

# Windows Components\Internet Explorer\Security Features\Scripted Window Security Restrictions - Internet Explorer Processes

control 'Computer_160' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_WINDOW_RESTRICTIONS' do
    its('Reserved') { should eq "1" }
  end
end

# Turn off location

control 'Computer_161' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors' do
    its('DisableLocation') { should eq 1 }
  end
end

# Turn off location scripting

control 'Computer_162' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors' do
    its('DisableLocationScripting') { should eq 1 }
  end
end

# Turn off sensors

control 'Computer_163' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors' do
    its('DisableSensors') { should eq 1 }
  end
end

# Automatic Maintenance WakeUp Policy

control 'Computer_164' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Task Scheduler\\Maintenance' do
    its('WakeUp') { should eq 1 }
  end
end

# Turn off Automatic Download and Update of Map Data

control 'Computer_165' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Maps' do
    its('AutoDownloadAndUpdateMapData') { should eq 0 }
  end
end

# Turn off unsolicited network traffic on the Offline Maps settings page

control 'Computer_166' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Maps' do
    its('AllowUntriggeredNetworkTrafficOnSettingsPage') { should eq 0 }
  end
end
