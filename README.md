# Project Alenaify

Make Windows 10 like Windows 7! This utility prevents Windows 10 from doing background tasks when it is idling by removing certain components and configuring certain things. You can expect a much faster Windows 10 system that also saves energy. This project will work on both offline (a Windows installation that is not currently active) or online (currently running Windows installation).

In addition, even after running all the actions, you can still expect the full Windows 10 experience, including:

- UWP, Windows Store, Xbox, and Store Purchases.
- Windows Update and DISM.

This utility requires PowerShell and has to be run on a Windows installation. The version 5.1 of PowerShell bundled in recent versions of Windows 10 will do. For online operations, this utility additionally requires `psexec64` from [Microsoft SysInternals](https://live.sysinternals.com) and `PowerRun_x64` from [Sordum](https://www.sordum.org/9416/powerrun-v1-4-run-with-highest-privileges/).

## System Requirements

Alenaify will only run on Windows 10 Anniversary Update (version 1607) or later. However, Alenaify can be applied to the initial release of Windows 10 (version 1507).

Only x64 version of Windows 10 are supported, both for execution and target. **ARM and 32-bit Windows 10 are not supported**: running Alenaify on those versions of Windows will lead to an undefined behaviour.

## Usage

Mount or connect the disk that contains a Windows 10 installation, and run the following in PowerShell:

```
.\Alenaify.ps1 -image (Mounted Windows Installation) (actions)
.\Alenaify.ps1 -online (actions)
```

Where:

- `(Mounted Windows Installation)`  
  Is the root directory where Windows is installed (e.g. the directory that contains the `Windows` and `Program Files` folder to be serviced.
- `-online`  
  To alenaify the currently running Windows installation.
- `(actions)`
  Is one of these:
  - `-all`
    Perform all actions.
  - `-include (actions)`
    Perform only the specified actions. `(actions)` is a comma-separated string of the actions to be performed.
  - `-exclude (actions)`
    Perform all actions except the specified one. `(actions)` is a comma-separated string of the actions to be excluded.

As this script is unsigned, you might need to set the correct execution policy to execute this script.

Also note that the **PowerShell host might hold a handle to the mounted registry hive**. If either of the last two lines of the output shows "Access Denied", close the PowerShell window host that was used to run this script, and run `unload-registry.bat` as administrator.

**Do not run on a freshly sysprep-ed image.**
The first stage of Windows setup will refuse to proceed otherwise. Instead, let the installed image boots until it enters the first screen of OOBE. Then shutdown (press Shift + F10, and type `shutdown /s /t 0`), and apply Alenaify.

**Updates will undo component removal changes** (but not configuration changes), even for security/cummulative updates. *Alenaify can be reapplied after updates*.

## Actions

The following are actions that will be carried on by Alenaify, explaining their actions, purposes, and caveats (if any).

- `RemoveOneDriveSetup`  
  **Actions:** Removes `OneDriveSetup.exe`.  
  **Purpose:** Windows 10 installs OneDrive *per user account*. The installer also tax the CPU to 100% for several minutes even on a high end PCs. If you often creates Windows user accounts for testing then the time taken by OneDriveSetup will add up. OneDrive installer for Windows is always downloadable from OneDrive's website.

- `RemoveRemoveSmartScreen`  
  **Actions:** Removes `smartscreen.exe`.  
  **Purpose:** Windows SmartScreen will create a checksum of a downloaded file everytime the file gets opened from Windows Explorer, which will cause significant delay for large files downloaded from the internet.

- `RemoveWaaS`  
  **Actions:** Removes files in System32 folder whose name begins with `WaasMedic`.  
  **Purpose:** The WaaS component is responsible for automatically re-enabling Windows Update service after a certain amount of time. Removing this component will keep Windows Update service stays disabled.

- `RemoveNGenTask`  
  **Actions:** Removes `ngentasklauncher.dll`.  
  **Purpose:** NGen can help optimize performance of .NET Framework applications by doing ahead of time compilations. However, it often goes out of hand by hogging the CPU for prolonged amount of time, and it often starts arbitrarily anytime it wishes to start, even when the computer is battery powered.  
  **Caveats:** .NET Framework 4.0 applications won't be AOT-compiled automatically. However, NGen can always be run manually, and many .NET Framework 4.0 based applications will run NGen anyway.

- `RemoveDiagSvc`  
  **Actions:** Removes `diagsvc.dll`, `dps.dll`, and `wdi.dll`.  
  **Purpose:** These services collects trace data in the background for various system diagnostics and telemetry. Windows troubleshooting utilities also uses these components. They typically doesn't hog CPU that much, but nevertheless still uses a considerable amount of CPU sometimes.  
  **Caveats:** Windows troubleshooting utilities will not work. Certain Windows features that depends on trace data such as `powercfg /sleepstudy` will not be able to generate the report.

- `RemoveWinDefend`  
  **Actions:** Removes `Program Files\Windows Defender`.  
  **Purpose:** Windows Defender Antivirus drastically slows down operations that are disk-bound (IO heavy), such as accessing many files. It also automatically deletes suspected files, even if they're false positive. It's real-time scan feature can only be turned off temporarily, and it occasionally does not obey the "disable real-time scan" configuration from Group Policy.

- `RemoveSecurityCenter`  
  **Actions:** Removes `WscSvc.dll`, `SecurityHealthService.exe`, and `SecurityHealthSystray.exe`.  
  **Purpose:** Prevent Windows from complaining that no antivirus solution is installed.  
  **Caveats:** Windows Security Center settings will not work.

- `RemoveWinsat`  
  **Actions:** Removes `WinSat.exe`.  
  **Purpose:** WinSAT is a benchmarking tool introduced in Vista, but deprecated in Windows 8.1 and discontinued in Windows 10. Windows 10 does not even include a means to access WinSAT data, yet WinSAT is still configured to run when the computer is idle. As a benchmarking tool, it will of course stress the components that it measures.

- `RemoveDeviceSetupManager`  
  **Actions:** Removes `DeviceSetupManager.dll`  
  **Purpose:** Device Setup Manager is responsible for automatically installing and updating drivers and its associated store applications (for UWD/DCH drivers) without user's confirmation. For some hardware that requires customized drivers with custom configuration, this has the potential to overwrite those configurations with the generic one. You can disable Windows Update service as well to disable this behaviour, but then you will lose access to Windows Store. Device drivers can still be automatically obtained from Windows Update by using Device Manager.

- `RemoveCompatTelemetry`  
  **Actions:** Removes `CompatTelRunner.exe`  
  **Purpose:** The Compatibility Telemetry collects information about installed applications in your system and sending this information to Microsoft for analytical purposes. This process often runs arbitrarily at any time, and it consumes a considerable amount of CPU time.

- `DisableCrashLog`  
  **Actions:** Set the `Control\CrashControl\EnableLogFile` registry value to 0.  
  **Purpose:** Disables minidump actions log (upon crashes, dump files will still be collected). In certain revisions of Windows 10 version 2004/20H2, it a bug that slows down the system when this feature is enabled.

- `DisableSlowServices`  
  **Actions:** Disable the "Windows Search" and "SysMain" (formerly known as "SuperFetch") services.  
  **Purpose:** Windows Search does full text indexing on your document's contents in the background, which consumes both CPU time and disk IO capacity. SysMain creates caches for launched applications, supposedly to speed up boot process, but in reality it only creates memory and disk space overhead (up to 1 GB in some cases), while actually detrimental to boot speed performance on SSD boot drives.  
  **Caveat:** Windows' built-in full text indexing no longer works. Search by file name still works fine, and so does content-based search (only the latter will perform slowly due to the lack of indexes).

- `DisableWinUpdateConfig`  
  **Actions:** Set the following Windows Update registry settings to "1": `ExcludeWUDriversInQualityUpdate`, `NoAutoUpdate`, `AUOptions`, `UseWUServer`. Also set `WUServer` to `http://nonexistent`.  
  **Purpose:** Prevents Windows Update from automatically update the Windows and installing drivers (some drivers will still be automatically installed, especially GPU drivers, unless the `RemoveDeviceSetupManager` action is also performed), even when Windows Update service is running. Updates can still be installed manually.

- `DisableWinUpdateServices`  
  **Actions:** Disable "Windows Update" service.  
  **Purpose:** Prevents APPX Deployment Service from running. It is best to exclude this action if the `DisableWinUpdateConfig` and `RemoveDeviceSetupManager` is also performed.  
  **Caveats:** Disables Windows Store installation and updates and prevents add optional features from working.