# This script is a minimalistic and butchered version of FLAREVM belonging to MANDIANT. 
# I just altered bits and pieces to suit my own initial PC setup of tools. 
# Credits goes to the author of the code...
# https://github.com/mandiant/flare-vm/tree/master/flarevm.win10.installer.fireeye

$ErrorActionPreference = 'Continue'

function InitialSetup {

  # Check to make sure script is run as administrator
  Write-Host "[+] Checking if script is running as administrator.."
  $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
  if (-Not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERR] Please run this script as administrator`n" -ForegroundColor Red
    Read-Host  "Press any key to continue"
    exit
  }

  # Check to make sure host is supported
  Write-Host "[+] Checking to make sure Operating System is compatible"
  if (-Not (((Get-WmiObject -class Win32_OperatingSystem).Version -eq "6.1.7601") -or ([System.Environment]::OSVersion.Version.Major -eq 10))){
    Write-Host "`t[ERR] $((Get-WmiObject -class Win32_OperatingSystem).Caption) is not supported, please use Windows 10" -ForegroundColor Red
    exit
  } else {
    Write-Host "`t$((Get-WmiObject -class Win32_OperatingSystem).Caption) supported" -ForegroundColor Green
  }
 
  # Basic system setup
  Update-ExecutionPolicy Unrestricted

  #### Add timestamp to PowerShell prompt ####
  Write-Host "[+] Updating PowerShell prompt..." -ForegroundColor Green
  $psprompt = @"
  function prompt
  {
      Write-Host "grandMasterPC " -ForegroundColor Green -NoNewLine
      Write-Host `$(get-date) -ForegroundColor Green
      Write-Host  "PS" `$PWD ">" -nonewline -foregroundcolor White
      return " "
  }
"@
  New-Item -ItemType File -Path $profile -Force | Out-Null 
  Set-Content -Path $profile -Value $psprompt
  # Add timestamp to cmd prompt
  iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Y21kIC9jICdzZXR4IFBST01QVCBGTEFSRSRTJGQkcyR0JF8kcCQrJGcn"))) | Out-Null
  Write-Host "[+] Timestamps added to cmd prompt and PowerShell" -ForegroundColor Green

  #### Fix shift+space in powershell
  Set-PSReadLineKeyHandler -Chord Shift+Spacebar -Function SelfInsert
  Write-Host "[+] Fixed shift+space keybinding in PowerShell" -ForegroundColor Green

  #### Enable script block logging ####
  Write-Host "[+] Enabling PS script block logging..." -ForegroundColor Green
  # Should be PS >5.1 now, enable transcription and script block logging
  # More info: https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html
  if ($PSVersionTable -And $PSVersionTable.PSVersion.Major -ge 5) {
      $psLoggingPath = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell'
      if (-Not (Test-Path $psLoggingPath)) {
          New-Item -Path $psLoggingPath -Force | Out-Null
      }
      
      $psLoggingPath = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription'
      if (-Not (Test-Path $psLoggingPath)) {
          New-Item -Path $psLoggingPath -Force | Out-Null
      }
      
      New-ItemProperty -Path $psLoggingPath -Name "EnableInvocationHeader" -Value 1 -PropertyType DWORD -Force | Out-Null
      New-ItemProperty -Path $psLoggingPath -Name "EnableTranscripting" -Value 1 -PropertyType DWORD -Force | Out-Null
      New-ItemProperty -Path $psLoggingPath -Name "OutputDirectory" -Value (Join-Path ${Env:UserProfile} "Desktop\PS_Transcripts") -PropertyType String -Force | Out-Null

      $psLoggingPath = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
      if (-Not (Test-Path $psLoggingPath)) {
          New-Item -Path $psLoggingPath -Force | Out-Null
      }
      
      New-ItemProperty -Path $psLoggingPath -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWORD -Force | Out-Null
      Write-Host "`t[i] PowerShell transcripts will be saved to the desktop in PS_Transcripts." -ForegroundColor Green
  }

  #### Set file associations ####
  Write-Host "[+] Setting file associations..." -ForegroundColor Green
  # Zip
  $7zip = "${Env:ProgramFiles}\7-Zip\7zFM.exe"
  if (Test-Path $7zip) {
      $7zipfiletype = "7zFM.exe"
      cmd /c assoc .zip=$7zipfiletype | Out-Null
      cmd /c assoc .7z=$7zipfiletype | Out-Null
      cmd /c assoc .tar=$7zipfiletype | Out-Null
      cmd /c assoc .bz=$7zipfiletype | Out-Null
      cmd /c assoc .gz=$7zipfiletype | Out-Null
      cmd /c assoc .gzip=$7zipfiletype | Out-Null
      cmd /c assoc .bzip=$7zipfiletype | Out-Null
      cmd /c @"
          ftype $7zipfiletype="$7zip" "%1" "%*" > NUL
"@
      New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
      Set-ItemProperty -Path "HKCR:\$7zipfiletype" -Name "(DEFAULT)" -Value "$7zipfiletype file" -Force | Out-Null
      Write-Host "`t[i] 7zip -> .zip" -ForegroundColor Green
  }
}

function Main {
    
  
    InitialSetup

    return 0
  }
  
  
  Main