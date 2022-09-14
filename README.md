## Powershell-One-Liner-For-Incident-Response
Useful Powershell Commands For Detection & Response

## Baselining
```
Get-ChildItem | Get-FileHash | Export-Csv -Path F:\old.csv
Get-ChildItem | Get-FileHash | Export-Csv -Path F:\new.csv

Note - Use Case - Compare with original configuration file to detect unauthorized changes.
Compare-Object -ReferenceObject (Get-Content -Path F:\old.csv) -DifferenceObject (Get-Content -Path F:\new.csv)
```
