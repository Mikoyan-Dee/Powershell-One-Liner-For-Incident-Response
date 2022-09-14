## Powershell-One-Liner-For-Incident-Response
Useful Powershell Commands For Detection & Response

## Baselining
```
Get-ChildItem | Get-FileHash | Export-Csv -Path F:\old.csv
Get-ChildItem | Get-FileHash | Export-Csv -Path F:\new.csv

#Use Case - Compare with original configuration file to detect unauthorized changes.
Compare-Object -ReferenceObject (Get-Content -Path F:\old.csv) -DifferenceObject (Get-Content -Path F:\new.csv)
```

## Process Investigation
```

#Use Case - Child & Parent Process Relationship Investigation

Get-WmiObject -class win32_process |select name,ProcessID,ParentProcessID,@{e={$_.GetOwner().User}}                          #finding process with ID,ParentID,associated_user
Get-WmiObject -Class Win32_Process |select-object PSComputerName,name,parentprocessid,executablepath                         #finding process with executablepath
Get-WmiObject -Class Win32_Process -filter "name='svchost.exe'" |select-object parentprocessid,executablepath,commandline    #svchost process investigation
```
