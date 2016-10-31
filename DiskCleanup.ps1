<#

.SYNOPSIS
Cleans up filesystem of common large and temporary files.

.DESCRIPTION
Cleans up filesystem of common large and temporary files.

.NOTES


#>
param ([switch]$componentcleanup)

Function Get-FreeSpace {
    param (
        $Driveletter,
        [ValidateSet("KB","MB","GB")]$unit
        )
    $size = (Get-WmiObject win32_logicaldisk | ? {$_.DeviceID -eq ("$Driveletter" + ":")}).Freespace / '{0}' -f ("1" + $unit)
    Return ('{0:N2}' -f $size)
}


Function Remove-WindowsTempFiles{
    #Cleanup Windows Temp
    try{
        Remove-Item -recurse $env:systemdrive\Windows\Temp\* -confirm:$false -ErrorAction SilentlyContinue
    }
    catch [System.IO.IOException]{}
    try{
        #Cleanup windows logs
        get-process -Name TrustedInstaller -ErrorAction SilentlyContinue | stop-process -confirm:$false -force -ErrorAction SilentlyContinue
        Remove-Item -recurse $env:systemdrive\Windows\logs\* -Confirm:$false -Force -ErrorAction SilentlyContinue
        while ((get-service TrustedInstaller).Status -ne "Running"){
            start-service TrustedInstaller
        }

    }
    catch [System.IO.IOException]{}
}

Function Get-UserProfiles {
    (Get-WMIObject Win32_UserProfile | ? {$_.localpath -notlike "*systemprofile" -and $_.localpath -notlike "*Administrator" -and $_.localpath -notlike "*NetworkService" -and $_.localpath -notlike "*LocalService" -and $_.localpath -notlike "*$env:USERNAME"-and $_.loaded -eq $false})
}
if (!((get-host).Version).Major -gt 4){
    "requires powershell v4 or higher"
    exit
}


#Cleanup User Profiles
Function Remove-UserProfiles {
    while ((Get-UserProfiles).count -gt 0){
       try{
            (Get-WMIObject Win32_UserProfile | ? {$_.localpath -notlike "*systemprofile" -and $_.localpath -notlike "*Administrator" -and $_.localpath -notlike "*NetworkService" -and $_.localpath -notlike "*LocalService" -and $_.localpath -notlike "*$env:USERNAME" -and $_.loaded -eq $false}).delete()
        }
       Catch [System.Management.Automation.MethodInvocationException]{
            break
        }
    }
}
#Clean Recycle Bin
Function Clear-RecycleBin {
    $Recycler = (New-Object -ComObject Shell.Application).NameSpace(0xa)
    $Recycler.items() | foreach { rm $_.path -force -recurse }
}

#Clean IIS Logs
function Clear-IISLogs {
    try {
        get-childitem -recurse 'C:\inetpub\logs' -erroraction stop | ? {$_.Name -like "u_ex*"} | Remove-Item -force -ErrorAction SilentlyContinue
    }
    catch [System.IO.IOException]{

    }
    catch [System.Management.Automation.ItemNotFoundException]{

    }
}

function Clear-ErrorReports {
    try {
        Get-Item $env:windir\Memory.dmp -ErrorAction stop | Remove-Item -force
    }
    catch [System.Management.Automation.ItemNotFoundException]{

    }

    try {
        Get-childitem $env:ALLUSERSPROFILE\Microsoft\Windows\WER\ | Remove-Item -recurse -force
    }
    catch [System.IO.IOException]{
    }

}

function Component-Cleanup {
    $OS = (Get-WmiObject Win32_OperatingSystem).Caption
    switch -Wildcard ($OS){
        "*2012*"{
            dism.exe /online /Cleanup-Image /StartComponentCleanup
        }

        "*2008 R2*" {
            if (!(test-path 'C:\windows\system32\cleanmgr.exe') -or (test-path C:\windows\system32\en-us\cleanmgr.exe.mui)){
                copy-item 'C:\Windows\winsxs\amd64_microsoft-windows-cleanmgr_31bf3856ad364e35_6.1.7600.16385_none_c9392808773cd7da\cleanmgr.exe' 'C:\windows\system32\cleanmgr.exe' -force -confirm:$false
                copy-item 'C:\Windows\winsxs\amd64_microsoft-windows-cleanmgr.resources_31bf3856ad364e35_6.1.7600.16385_en-us_b9cb6194b257cc63\cleanmgr.exe.mui' 'C:\windows\system32\en-us\cleanmgr.exe.mui' -force -confirm:$false
                }
            start-process -filepath "cleanmgr.exe" -ArgumentList "/verylowdisk" -wait
            }
        }

}

function Clear-FontCache {
  $fontfiles  = get-childitem "$($env:systemdrive)\Windows\ServiceProfiles\LocalService\AppData\Local" -recurse -filter "*FontCache*"
  $fontfiles | % {
      $acl = get-acl $_.FullName
      $permission = "$($env:username)","FullControl","Allow"
      $accessrule = New-Object system.security.accesscontrol.filesystemaccessrule $permission
      $acl.AddAccessRule($accessrule)
      $acl | Set-Acl $_.FullName -erroraction SilentlyContinue
  }
  stop-service "BITS"
  stop-service "FontCache"
  stop-service "SENS" -force
  stop-service "COMSysApp"
  stop-service "EventSystem" -force
  Remove-Item "$($env:systemdrive)\Windows\ServiceProfiles\LocalService\AppData\Local\*.dat" -force -confirm:$false -erroraction SilentlyContinue
  start-service "EventSystem"
  start-service "BITS"
  start-service "FontCache"
  start-service "SENS"
  start-service "COMSysApp"

}

function Clear-CCMCache {
    $ccmfolders = Get-Childitem "$($env:systemroot)\ccmcache" -erroraction SilentlyContinue
      $ccmfolders | % {
          $acl = get-acl $_.FullName
          $permission = "$($env:username)","FullControl","Allow"
          $accessrule = New-Object system.security.accesscontrol.filesystemaccessrule $permission
          $acl.AddAccessRule($accessrule)
          $acl | Set-Acl $_.FullName -erroraction SilentlyContinue
          Remove-Item $_.FullName -recurse -force -confirm:$false -erroraction SilentlyContinue
      }
}

function Clear-Sophos {
  $sophoscache = Get-ChildItem "$($env:programdata)\Sophos\AutoUpdate\Cache"
  $sophoscache | % {
      $acl = get-acl $_.FullName
      $permission = "$($env:username)","FullControl","Allow"
      $accessrule = New-Object system.security.accesscontrol.filesystemaccessrule $permission
      $acl.AddAccessRule($accessrule)
      $acl | Set-Acl $_.FullName -erroraction SilentlyContinue
      Remove-Item $_.FullName -recurse -force -confirm:$false -erroraction SilentlyContinue
  }
}

function Component-Cleanup2012 {
    $OS = (Get-WmiObject Win32_OperatingSystem).Caption
    switch -Wildcard ($OS){
        "*2012*"{
            dism.exe /online /Cleanup-Image /StartComponentCleanup
        }
      }
}

function Find-SQLDatabases {
    $databases = Get-ChildItem -recurse "$($env:programfiles)\Microsoft SQL Server" -erroraction SilentlyContinue | ? {$_.Name -like "*.*df" -and $_.Name -inotlike "master.*df" -and $_.Name -inotlike "model.*df" -and $_.Name -inotlike "msdbdata.*df"}
    if ($databases) {
      Write-Host  -backgroundcolor RED "WARNING: The Following databases exist on $($env:systemdrive) and should be moved."
      $databases | sort length -descending  | select Name,@{Name="DB Size MB";Expression={[math]::round($($_.length / 1MB),2)}} -first 5
    }
}

#Get Free Space before clearing anything.
$initialsize = Get-FreeSpace -Driveletter C -unit GB

#Check if running as Administrator
#if ($host.UI.RawUI.WindowTitle -notlike "Administrator:*") {
#    throw "Powershell not running as Administrator. `n Run as Administrator and try again"
#}

#Begin Cleanup
Remove-WindowsTempFiles
Remove-UserProfiles
Clear-RecycleBin
Clear-IISLogs
Clear-ErrorReports
Clear-FontCache
Clear-CCMCache
Clear-Sophos
Component-Cleanup2012
Find-SQLDatabases

if ($componentcleanup){
  Component-Cleanup
}

#End Cleanup

$Newsize = Get-FreeSpace -Driveletter C -unit GB

#Calculate Space Saved.
$Clearedspace =  '{0:N2} GB' -f  ($Newsize - $initialsize )
Write-Host "Successfully Cleared $Clearedspace"
