## Powershell-One-Liner-For-Incident-Response
Useful Powershell Commands For Detection & Response

## Baselining
Use Case - Compare with original configuration file to detect unauthorized changes.
```
Get-ChildItem | Get-FileHash | Export-Csv -Path F:\old.csv
Get-ChildItem | Get-FileHash | Export-Csv -Path F:\new.csv
Compare-Object -ReferenceObject (Get-Content -Path F:\old.csv) -DifferenceObject (Get-Content -Path F:\new.csv)
```

## Process Investigation
Use Case - Child & Parent Process Relationship Investigation.
```
Get-WmiObject -class win32_process |select name,ProcessID,ParentProcessID,@{e={$_.GetOwner().User}}                          #finding process with ID,ParentID,associated_user
Get-WmiObject -Class Win32_Process |select-object PSComputerName,name,parentprocessid,executablepath                         #finding process with executablepath
Get-WmiObject -Class Win32_Process -filter "name='svchost.exe'" |select-object parentprocessid,executablepath,commandline    #svchost process investigation
```

## Unmanaged PowerShell 
Use Case - Find out malicious powershell module loaded (system.management.automation.dll) in non standard process.
```
Get-Process | Where {$_.modules -like "*system.management.automation*"}| Where {$_.ProcessName -ne "powershell"} | select name,id,modules | fl
```

## Alternate Data Streams (ADS)
Use Case - Detection of Hiding Artifacts with Alternate Data Streams.
```
Get-Item .\file.txt -Stream * | where Stream -ne ':$DATA' |select-object PSChildName
```

## Scheduled Task
Use Case - Detection of Malicious Scheduled Task.
```
Get-ScheduledTask | Where {$_.State -eq "Running"} | Select-Object TaskName, TaskPath, State, Author | Where {$_.Author -ne $null}
```

## File Analysis
Use Case - Identify the correct file signature to spot masquerading.

#JPG Signature
FF D8 FF E0 (in first byte) - JPG 
FF D8 FF E1 (in first byte) - JPG
FF D8 FF E2 (in first byte) - JPG
FF D8 FF E8 (in first byte) - JPG

#Executable_File Signature
4D 5A (MZ in first byte) - Executable File Window

#PDF Signature
%PDF-1.0  (in first byte) - PDF file
25 50 44 46 - %PDF
```
Format-Hex -Path .\file.file
```
