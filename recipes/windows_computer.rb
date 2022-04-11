# Force automatic setup for all users

registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WorkFolders' do
  values [{ name: 'AutoProvision', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Select when Quality Updates are received
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate' do
  values [{ name: 'DeferQualityUpdates', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Select when Preview Builds and Feature Updates are received
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate' do
  values [{ name: 'DeferFeatureUpdates', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Manage preview builds
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate' do
  values [{ name: 'ManagePreviewBuilds', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Hide the Virus and threat protection area
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Virus and threat protection' do
  values [{ name: 'UILockdown', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Hide the Ransomware data recovery area
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Virus and threat protection' do
  values [{ name: 'HideRansomwareRecovery', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Hide Windows Security Systray
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray' do
  values [{ name: 'HideSystray', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Hide non-critical notifications
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' do
  values [{ name: 'DisableEnhancedNotifications', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Hide all notifications
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' do
  values [{ name: 'DisableNotifications', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Hide the Firewall and network protection area
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Firewall and network protection' do
  values [{ name: 'UILockdown', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Hide the Family options area
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options' do
  values [{ name: 'UILockdown', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Specify contact website
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Enterprise Customization' do
  values [{ name: 'Url', type: :string, data: '' }]
  action :delete
end

# Specify contact phone number or Skype ID
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Enterprise Customization' do
  values [{ name: 'Phone', type: :string, data: '' }]
  action :delete
end

# Specify contact email address or Email ID
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Enterprise Customization' do
  values [{ name: 'Email', type: :string, data: '' }]
  action :delete
end

# Specify contact company name
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Enterprise Customization' do
  values [{ name: 'CompanyName', type: :string, data: '' }]
  action :delete
end

# Configure customized notifications
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Enterprise Customization' do
  values [{ name: 'EnableForToasts', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Configure customized contact information
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Enterprise Customization' do
  values [{ name: 'EnableInApp', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Hide the TPM Firmware Update recommendation.
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device security' do
  values [{ name: 'DisableTpmFirmwareUpdateWarning', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Hide the Security processor (TPM) troubleshooter page
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device security' do
  values [{ name: 'HideTPMTroubleshooting', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Hide the Secure boot area
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device security' do
  values [{ name: 'HideSecureBoot', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Hide the Device security area
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device security' do
  values [{ name: 'UILockdown', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Disable the Clear TPM button
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device security' do
  values [{ name: 'DisableClearTpmButton', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Prevent users from modifying settings
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection' do
  values [{ name: 'DisallowExploitProtectionOverride', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Hide the App and browser protection area
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection' do
  values [{ name: 'UILockdown', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Hide the Account protection area
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Account protection' do
  values [{ name: 'UILockdown', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Allow Remote Shell Access
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS' do
  values [{ name: 'AllowRemoteShellAccess', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Turn On Compatibility HTTPS Listener
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service' do
  values [{ name: 'HttpsCompatibilityListener', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Turn On Compatibility HTTP Listener
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service' do
  values [{ name: 'HttpCompatibilityListener', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Disallow WinRM from storing RunAs credentials
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service' do
  values [{ name: 'DisableRunAs', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Allow unencrypted traffic
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service' do
  values [{ name: 'AllowUnencryptedTraffic', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Allow remote server management through WinRM
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service' do
  values [{ name: 'AllowAutoConfig', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Allow Basic authentication
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service' do
  values [{ name: 'AllowBasic', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Disallow Digest authentication
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client' do
  values [{ name: 'AllowDigest', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Allow unencrypted traffic
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client' do
  values [{ name: 'AllowUnencryptedTraffic', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Allow Basic authentication
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client' do
  values [{ name: 'AllowBasic', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Turn on Script Execution
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell' do
  values [{ name: 'ExecutionPolicy', type: :string, data: 'RemoteSigned' }]
  action :create
  recursive true
end

# Turn on PowerShell Transcription
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Transcription' do
  values [{ name: 'EnableTranscripting', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Turn on PowerShell Script Block Logging
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' do
  values [{ name: 'EnableScriptBlockLogging', type: :dword, data: '1' }]
  action :create
  recursive true
end

registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' do
  values [{ name: 'EnableScriptBlockInvocationLogging', type: :dword, data: '0' }]
  action :delete
end

# Turn off Windows Mobility Center
registry_key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\MobilityCenter' do
  values [{ name: 'NoMobilityCenter', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Do not automatically start Windows Messenger initially
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Messenger\Client' do
  values [{ name: 'PreventAutoRun', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Do not allow Windows Messenger to be run
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Messenger\Client' do
  values [{ name: 'PreventRun', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Prevent Media Sharing
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsMediaPlayer' do
  values [{ name: 'PreventLibrarySharing', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Prevent Automatic Updates
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsMediaPlayer' do
  values [{ name: 'DisableAutoUpdate', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Do Not Show First Use Dialog Boxes
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsMediaPlayer' do
  values [{ name: 'GroupPrivacyAcceptance', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Prevent Windows Media DRM Internet Access
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WMDRM' do
  values [{ name: 'DisableOnline', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Configure the mode of automatically signing in and locking last interactive user after a restart or cold boot
registry_key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'AutomaticRestartSignOnConfig', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Display information about previous logons during user logon
registry_key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'DisplayLastLogonInfo', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Disable or enable software Secure Attention Sequence
registry_key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'SoftwareSASGeneration', type: :dword, data: '3' }]
  action :create
  recursive true
end

# Turn off shared components
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{ name: 'DisableSharedComponent', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Turn off logging via package settings
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{ name: 'DisableLoggingFromPackage', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Turn off creation of System Restore checkpoints
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{ name: 'LimitSystemRestoreCheckpointing', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Remove browse dialog box for new source
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{ name: 'DisableBrowse', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Prohibit User Installs
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{ name: 'DisableUserInstalls', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Prohibit use of Restart Manager
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{ name: 'DisableAutomaticApplicationShutdown', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Prohibit rollback
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{ name: 'DisableRollback', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Prohibit removal of updates
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{ name: 'DisablePatchUninstall', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Prohibit non-administrators from applying vendor signed updates
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{ name: 'DisableLUAPatching', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Prevent users from using Windows Installer to install updates and upgrades
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{ name: 'DisablePatch', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Prevent Internet Explorer security prompt for Windows Installer scripts
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{ name: 'UILockdown', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Always install with elevated privileges
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{ name: 'AlwaysInstallElevated', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Allow users to use media source while elevated
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{ name: 'AllowLockdownMedia', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Allow users to patch elevated products
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{ name: 'AllowLockdownPatch', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Allow users to browse for source while elevated
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{ name: 'AllowLockdownBrowse', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Allow user control over installs
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{ name: 'EnableUserControl', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Allow Windows Ink Workspace
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsInkWorkspace' do
  values [{ name: 'AllowWindowsInkWorkspace', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Allow suggested apps in Windows Ink Workspace
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsInkWorkspace' do
  values [{ name: 'AllowSuggestedAppsInWindowsInkWorkspace', type: :dword, data: '0' }]
  action :create
  recursive true
end

# Configure Windows Defender SmartScreen
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System' do
  values [{ name: 'EnableSmartScreen', type: :dword, data: '1' }]
  action :create
  recursive true
end

registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System' do
  values [{ name: 'ShellSmartScreenLevel', type: :string, data: 'Block' }]
  action :create
  recursive true
end

# Prevent users and apps from accessing dangerous websites
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' do
  values [{ name: 'EnableNetworkProtection', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Configure protected folders
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access' do
  values [{ name: 'ExploitGuard_ControlledFolderAccess_ProtectedFolders', type: :dword, data: '1' }]
  action :create
  recursive true
end

# Configure Controlled folder access
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access' do
  values [{ name: 'EnableControlledFolderAccess', type: :dword, data: '1' }]
  action :create
  recursive true
end

registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options' do
  values [{ name: 'UILockdown', type: :dword, data: '1' }]
  action :create
  recursive true
end

registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options' do
  values [{ name: 'UILockdown', type: :dword, data: '1' }]
  action :create
  recursive true
end

registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options' do
  values [{ name: 'UILockdown', type: :dword, data: '1' }]
  action :create
  recursive true
end
