# Chef InSpec test for recipe wintel-2019::computer

# The Chef InSpec reference, with examples and extensive documentation, can be
# found at https://docs.chef.io/inspec/resources/

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

# Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services

control 'Computer_33' do
  describe registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\wcmsvc\\wifinetworkmanager\\config' do
    its('AutoConnectAllowedOEM') { should eq 0 }
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

# 