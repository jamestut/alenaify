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
    if ($null -eq (Get-Command $dep -ErrorAction SilentlyContinue)) {
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
    pskill -nobanner -t $Name
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
  
  # takeown so that we can modify permission
  takeown /f $AbsPath
  # if this is a folder, also do it recursively
  takeown /f $AbsPath /r /d y

  # icacls to grant the executor of this script full access to the file/folder, recursively
  icacls $AbsPath /grant *S-1-3-4:F /t

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

function Action-RemoveWaaS {
  Write-Host "Removing WaaS Medic ..."
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
  $svclist = @('diagsvc', 'diagsvc', 'WdiServiceHost', 'WdiSystemHost')
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
    Alenaify-Disable-Service -Name $svc
  }
}

function Action-DisableWinUpdateServices {
  Write-Host "Disable Windows Update service ..."
  Alenaify-Disable-Service -Name "wuauserv"
}

function Action-DisableWinUpdateConfig {
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

# main script
# get list of actions to execute
$AvailActions = @{ 
  RemoveOneDriveSetup      = 'Action-RemoveOneDriveSetup'; 
  RemoveWaaS               = 'Action-RemoveWaaS';
  RemoveNGenTask           = 'Action-RemoveNGenTask';
  RemoveDiagSvc            = 'Action-RemoveDiagSvc';
  RemoveWinDefend          = 'Action-RemoveWinDefend';
  RemoveSecurityCenter     = 'Action-RemoveSecurityCenter';
  RemoveWinsat             = 'Action-RemoveWinsat';
  RemoveCompatTelemetry    = 'Action-RemoveCompatTelemetry';
  DisableCrashLog          = 'Action-DisableCrashLog';
  DisableSlowServices      = 'Action-DisableSlowServices';
  DisableWinUpdateServices = 'Action-DisableWinUpdateServices';
  DisableWinUpdateConfig   = 'Action-DisableWinUpdateConfig';
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
  Check-Dependencies -Deps pskill, psexec
  if (-Not ($SkipPrivCheck)) {
    if (-Not (Is-System)) {
      # raise to system
      Write-Host "Restarting as SYSTEM privilege ..."
      psexec -s -accepteula powershell -ExecutionPolicy Unrestricted $PSCommandPath -Online -SkipPrivCheck -Include ($Actions.Keys -join ",")
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
