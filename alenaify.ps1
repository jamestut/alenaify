param(
  [Parameter(Mandatory = $true, ParameterSetName = "Online")]
  [switch]
  $Online,

  [Parameter(Mandatory = $false, ParameterSetName = "Online")]
  [switch]
  $SkipPrivCheck,

  [Parameter(Mandatory = $true, ParameterSetName = "Image")]
  [String]
  $Image,

  [Parameter(Mandatory = $false, ParameterSetName = "Image")]
  [String]
  $SystemHivePath = "mntSystem",

  [Parameter(Mandatory = $false, ParameterSetName = "Image")]
  [String]
  $SoftwareHivePath = "mntSoftware",
  
  [switch]
  $All,

  [String[]]
  $Include,

  [String[]]
  $Exclude
)

# common functions
function Check-Dependencies {
  param(
    [Parameter(Mandatory = $true)]
    [String[]]
    $Deps
  )
  foreach ($dep in $Deps) {
    if ($null -eq (Get-Command .\$dep -ErrorAction SilentlyContinue)) {
      Write-Host "Unable to find $dep.exe"
      Write-Host "Ensure that the following programs are in the same folder or PATH:"
      foreach ($dep2 in $Deps) {
        Write-Host " - $dep2.exe"
      }
      throw "Required dependencies not found."
    }
  }
}

function Is-System {
  $uname = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.ToUpper()
  return ($uname -eq "NT AUTHORITY\SYSTEM")
}

function Is-Administrator {
  $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Image-SanityCheck {
  $pathToTest = $('Windows', 'Program Files')
  foreach ($path in $pathToTest) {
    if (-Not (Test-Path "$Image\$path")) {
      throw "The $path folder not found in the specified image."
    }
  }
}

# common functions for actions
function Alenaify-Stop-Service {
  param(
    [Parameter(Mandatory = $true)]
    [String]
    $Name
  )
  if ($online) {
    Stop-Service -Name $Name -Force
  }
}

function Alenaify-Stop-Process {
  param(
    [Parameter(Mandatory = $true)]
    [String]
    $Name
  )
  if ($online) {
    .\pskill64 -accepteula -nobanner -t $Name
  }
}

function Alenaify-Disable-Service {
  param(
    [Parameter(Mandatory = $true)]
    [String]
    $Name
  )
  Alenaify-WriteRegValue -HiveType "SYSTEM" -Key "Services\$Name" -ValueName "Start" -Value 4 -Type "DWORD"
}

function Alenaify-Remove-File {
  param(
    [Parameter(Mandatory = $true)]
    [String]
    $RelativePath
  )
  if ($Online) {
    $AbsPath = "C:\$RelativePath"
  }
  else {
    $AbsPath = "$Image\$RelativePath"
  }

  # full access to OWNER RIGHTS
  $NewPerm = "*S-1-3-4:F"

  # takeown, but first,
  # check if file, folder, or non existent (for cleaner message)
  if (Test-Path -Path $AbsPath -PathType Leaf) {
    # file
    takeown /f $AbsPath
    icacls $AbsPath /grant $NewPerm
  } elseif (Test-Path -Path $AbsPath -PathType Container) {
    # folder
    takeown /f $AbsPath /r /d y
    icacls $AbsPath /grant $NewPerm /t
  } else {
    Write-Output "File $RelativePath not found. Skipping."
    return
  }

  Remove-Item -Path $AbsPath -Recurse
}

function Alenaify-WriteRegValue {
  param(
    [Parameter(Mandatory = $true)]
    [String]
    $HiveType,
    [Parameter(Mandatory = $true)]
    [String]
    $Key,
    [Parameter(Mandatory = $true)]
    [String]
    $ValueName,
    [Parameter(Mandatory = $true)]
    $Value,
    [Parameter(Mandatory = $true)]
    [String]
    $Type
  )

  # base key name
  $unkHiveErrMsg = "Unknown hive type."
  if ($Online) {
    switch ($HiveType) {
      "SYSTEM" { $BaseKey = "HKLM:\SYSTEM\CurrentControlSet" }
      "SOFTWARE" { $BaseKey = "HKLM:\SOFTWARE" }
      default { throw $unkHiveErrMsg }
    }
  }
  else {
    switch ($HiveType) {
      "SYSTEM" { $BaseKey = "HKLM:\$SystemHivePath\ControlSet001" }
      "SOFTWARE" { $BaseKey = "HKLM:\$SoftwareHivePath" }
      default { throw $unkHiveErrMsg }
    }
  }
  $AbsKey = "$BaseKey\$Key"

  # create key (folder) if not exists
  if (-Not(Test-Path $AbsKey)) {
    New-Item -Path $AbsKey -Force
  }
  Set-ItemProperty -Path $AbsKey -Name $ValueName -Value $Value -Type $Type
}

function Alenaify-MountReg {
  param(
    [Parameter(Mandatory = $true)]
    [String]
    $Hive,
    [Parameter(Mandatory = $true)]
    [String]
    $File
  )
  $ResolvHive = "HKLM\$Hive"
  reg load $ResolvHive $File
  if ($LASTEXITCODE -ne 0) {
    throw throw "Error mounting registry hive of the target image."
  }
}

function Alenaify-UnmountReg {
  param(
    [Parameter(Mandatory = $true)]
    [String]
    $Hive
  )
  $ResolvHive = "HKLM\$Hive"
  reg unload $ResolvHive
}

# action functions
function Action-RemoveOneDriveSetup {
  Write-Host "Removing OneDrive setup file ..."
  Alenaify-Remove-File -RelativePath "Windows\SysWOW64\OneDriveSetup.exe"
}

function Action-RemoveSmartScreen {
  Write-Host "Removing SmartScreen ..."
  Alenaify-Stop-Process -Name "smartscreen.exe"
  Alenaify-Remove-File -RelativePath "Windows\System32\smartscreen.exe"
}

function Action-RemoveWaaS {
  Write-Host "Removing WaaS Medic ..."
  Alenaify-Stop-Process -Name 'WaaSMedicAgent.exe'
  $filelist = @('WaaSMedicAgent.exe', 'WaaSMedicCapsule.dll', 'WaaSMedicPS.dll', 'WaaSMedicSvc.dll')
  foreach ($filename in $filelist) {
    Alenaify-Remove-File -RelativePath "Windows\System32\$filename"
  }
}

function Action-RemoveNGenTask {
  Write-Host "Removing .NET Framework NGEN scheduled task ..."
  Alenaify-Remove-File -RelativePath "Windows\Microsoft.NET\Framework64\v4.0.30319\ngentasklauncher.dll"
}

function Action-RemoveDiagSvc {
  Write-Host "Removing Diagnostic Services ..."
  $svclist = @('diagsvc', 'dps', 'WdiServiceHost', 'WdiSystemHost')
  foreach ($svc in $svclist) {
    Alenaify-Stop-Service -Name $svc -ErrorAction Continue
    Alenaify-Disable-Service -Name $svc -ErrorAction Continue
  }
  $filelist = @('diagsvc.dll', 'dps.dll', 'wdi.dll')
  foreach ($file in $filelist) {
    Alenaify-Remove-File -RelativePath "Windows\System32\$file"
  }
}

function Action-RemoveWinDefend {
  Write-Host "Removing Windows Defender ..."
  Alenaify-Stop-Service -Name "WinDefend" -ErrorAction Continue
  Alenaify-Disable-Service -Name "WinDefend" -ErrorAction Continue
  # this realtime scanning engine is the important one. fail to delete = fail!
  Alenaify-Remove-File -RelativePath "Program Files\Windows Defender\MsMpEng.exe"
  Alenaify-Remove-File -RelativePath "Program Files\Windows Defender" -ErrorAction Continue
}

function Action-RemoveSecurityCenter {
  Write-Host "Removing Windows Security Center ..."
  Alenaify-Stop-Service -Name "WscSvc" -ErrorAction Continue
  Alenaify-Remove-File -RelativePath "Windows\System32\wscsvc.dll"
  $filelist = @('SecurityHealthService.exe', 'SecurityHealthSystray.exe')
  foreach ($file in $filelist) {
    Alenaify-Stop-Process -Name $file
    Alenaify-Remove-File -RelativePath "Windows\System32\$file"
  }
}

function Action-RemoveWinsat {
  Write-Host "Removing WinSAT ..."
  Alenaify-Remove-File -RelativePath "Windows\System32\WinSAT.exe"
}

function Action-RemoveDeviceSetupManager {
  Write-Host "Removing Device Setup Manager ..."
  Alenaify-Stop-Service -Name "DsmSvc" -ErrorAction Continue
  Alenaify-Disable-Service -Name "DsmSvc" -ErrorAction Continue
  Alenaify-Remove-File -RelativePath "Windows\System32\DeviceSetupManager.dll"
}

function Action-RemoveCompatTelemetry {
  Write-Host "Removing Windows Compatibility Telemetry ..."
  Alenaify-Stop-Process -Name "CompatTelRunner.exe"
  Alenaify-Remove-File -RelativePath "Windows\System32\CompatTelRunner.exe"
}

function Action-DisableCrashLog {
  Write-Host "Disable dumpstack.log ..."
  Alenaify-WriteRegValue -HiveType "SYSTEM" -Key "Control\CrashControl" -ValueName "EnableLogFile" -Value 0 -Type "DWORD"
}

function Action-DisableSlowServices {
  Write-Host "Disable slow services ..."
  $serviceslist = @("WSearch", "SysMain")
  foreach ($svc in $serviceslist) {
    Alenaify-Stop-Service -Name $svc
    Alenaify-Disable-Service -Name $svc
  }
}

function Action-DisableWinUpdateServices {
  Write-Host "Disable Windows Update service ..."
  Alenaify-Disable-Service -Name "wuauserv"
}

function Action-DisableWinUpdateConfig {
  Write-Host "Disable Windows automatic update configurations ..."
  # exclude driver updates
  $NoDriverKeys = @('Microsoft\PolicyManager\current\device\Update', 
    'Microsoft\PolicyManager\default\Update', 
    'Microsoft\WindowsUpdate\UX\Settings', 
    'Policies\Microsoft\Windows\WindowsUpdate',
    'Microsoft\PolicyManager\default\Update')
  foreach ($key in $NoDriverKeys) {
    Alenaify-WriteRegValue -HiveType "SOFTWARE" -Key $key -ValueName "ExcludeWUDriversInQualityUpdate" -Value 1 -Type "DWORD"
  }
  # auto update overall
  $AUKey = "Policies\Microsoft\Windows\WindowsUpdate\AU"
  Alenaify-WriteRegValue -HiveType "SOFTWARE" -Key $AUKey -ValueName "NoAutoUpdate" -Value 1 -Type "DWORD"
  Alenaify-WriteRegValue -HiveType "SOFTWARE" -Key $AUKey -ValueName "AUOptions" -Value 1 -Type "DWORD"
  Alenaify-WriteRegValue -HiveType "SOFTWARE" -Key $AUKey -ValueName "UseWUServer" -Value 1 -Type "DWORD"
  Alenaify-WriteRegValue -HiveType "SOFTWARE" -Key $AUKey -ValueName "WUServer" -Value "http://nonexistent" -Type "String"
}

function Action-DisableSpeculativeCtrl {
  # disable spectre/meltdown mitigation
  Write-Host "Disable speculative control ..."
  $OSSpecCtrlKey = 'Control\Session Manager\Memory Management'
  Alenaify-WriteRegValue -HiveType "SYSTEM" -Key $OSSpecCtrlKey -ValueName "FeatureSettingsOverride" -Value 3 -Type "DWORD"
  Alenaify-WriteRegValue -HiveType "SYSTEM" -Key $OSSpecCtrlKey -ValueName "FeatureSettingsOverrideMask" -Value 3 -Type "DWORD"
  
  # disable for Hyper-V as well
  Alenaify-WriteRegValue -HiveType "SOFTWARE" -Key "Microsoft\Windows NT\CurrentVersion\Virtualization" -ValueName "MinVmVersionForCpuBasedMitigations" -Value "13.0" -Type "String"
}

function Action-FileSystemTuning {
  Write-Host "File system tuning ..."
  $FSTuneKey = 'Control\FileSystem'
  Alenaify-WriteRegValue -HiveType "SYSTEM" -Key $FSTuneKey -ValueName "NtfsDisable8dot3NameCreation" -Value 1 -Type "DWORD"
  Alenaify-WriteRegValue -HiveType "SYSTEM" -Key $FSTuneKey -ValueName "Win95TruncatedExtensions" -Value 0 -Type "DWORD"
  Alenaify-WriteRegValue -HiveType "SYSTEM" -Key $FSTuneKey -ValueName "NtfsDisableLastAccessUpdate" -Value 0x80000001 -Type "DWORD"
}

# main script
# get list of actions to execute
$AvailActions = @{ 
  RemoveOneDriveSetup      = 'Action-RemoveOneDriveSetup'; 
  RemoveSmartScreen        = 'Action-RemoveSmartScreen'; 
  RemoveWaaS               = 'Action-RemoveWaaS';
  RemoveNGenTask           = 'Action-RemoveNGenTask';
  RemoveDiagSvc            = 'Action-RemoveDiagSvc';
  RemoveWinDefend          = 'Action-RemoveWinDefend';
  RemoveSecurityCenter     = 'Action-RemoveSecurityCenter';
  RemoveWinsat             = 'Action-RemoveWinsat';
  RemoveCompatTelemetry    = 'Action-RemoveCompatTelemetry';
  RemoveDeviceSetupManager = 'Action-RemoveDeviceSetupManager';
  DisableCrashLog          = 'Action-DisableCrashLog';
  DisableSlowServices      = 'Action-DisableSlowServices';
  DisableWinUpdateServices = 'Action-DisableWinUpdateServices';
  DisableWinUpdateConfig   = 'Action-DisableWinUpdateConfig';
  DisableSpeculativeCtrl   = 'Action-DisableSpeculativeCtrl';
  FileSystemTuning         = 'Action-FileSystemTuning';
}
$Actions = @{}
if (($All) -or ($null -ne $Exclude)) {
  foreach ($item in $AvailActions.Keys) {
    $Actions[$item] = $null
  }
}
if ($null -ne $Include) {
  foreach ($act in $Include) {
    if (-not ($AvailActions.ContainsKey($act))) {
      throw "Unknown command: $act"
    }
    $Actions[$act] = $null
  }
}
if ($null -ne $Exclude) {
  foreach ($act in $Exclude) {
    if (-not ($Actions.ContainsKey($act))) {
      throw "Unknown command: $act"
    }
    $Actions.Remove($act)
  }
}
if ($Actions.Count -eq 0) {
  throw "Please specify action(s) to execute."
}

# if online, we need the dependencies and the privilege
if ($Online) {
  Set-Location $PSScriptRoot
  Check-Dependencies -Deps pskill64, powerrun_x64
  if (-Not ($SkipPrivCheck)) {
    if (-Not (Is-System)) {
      # raise to system
      Write-Host "Restarting as SYSTEM privilege ..."
      .\powerrun_x64 powershell.exe -ExecutionPolicy Unrestricted $PSCommandPath -Online -SkipPrivCheck -Include ($Actions.Keys -join ",")
    }
    exit
  }
}
else {
  if (-Not ($SkipPrivCheck)) {
    if (-Not (Is-Administrator)) {
      throw "Please run this script as administrator."
    }
  }
  Image-SanityCheck
  # mount target hive
  Write-Host "Loading hive of the target ..."
  try {
    Alenaify-MountReg -Hive $SystemHivePath -File "$Image\Windows\System32\config\SYSTEM"
    Alenaify-MountReg -Hive $SoftwareHivePath -File "$Image\Windows\System32\config\SOFTWARE"
  }
  catch {
    Alenaify-UnmountReg -Hive $SystemHivePath
    Alenaify-UnmountReg -Hive $SoftwareHivePath
    throw "Error mounting target registry hive."
  }
}

try {
  foreach ($action in $Actions.Keys) {
    Write-Host "--------------------------------"
    try {
      &$AvailActions[$action]
    }
    catch {
      Write-Error "Error executing '$action': $_"
    }
  }
}
finally {
  if ($null -ne $Image) {
    Alenaify-UnmountReg -Hive $SystemHivePath
    Alenaify-UnmountReg -Hive $SoftwareHivePath
  }
}

# pause so user can see the result
if ($Online -and $SkipPrivCheck) {
  pause
}
