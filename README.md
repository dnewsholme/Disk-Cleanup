# Disk Cleanup

This script will clean up a C:\ drive with low space.

## How to run
run from elevevated prompt
```powershell
(new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/ratchetnclank/Disk-Cleanup/master/DiskCleanup.ps1") | iex
```

## Windows Temp Files
It will clean files under C:\windows\temp and C:\windows\logs

## User Profiles
Removes all user profiles which aren't locked and/or default administrator accounts.

## Recycle bin
Clears all users recycle bin

## Windows Error Logs and memory dumps
Clears error logs and dumps from the device.

## Clears down winsxs
Uses Disk cleanup utility to clear down winsxs.
