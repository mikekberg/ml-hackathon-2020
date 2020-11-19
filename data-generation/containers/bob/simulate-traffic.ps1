$domains = Get-Content .\top500Domains.csv | ConvertFrom-Csv
$start = (Get-Date)
$runTime = ($env:DATA_GENERATIONS_MINUTES -as [int])

Write-Output $env:DATA_GENERATIONS_MINUTES

while (((Get-Date).Subtract($start).TotalMinutes) -lt $runTime) { 
    $site = $domains[(Get-Random -Minimum 0 -Maximum $($domains.Length - 1))]."Root Domain" 
    Write-Output "Navigating to $site"
    Invoke-WebRequest $site | Out-Null
    Start-Sleep -Milliseconds $(Get-Random -Minimum 1000 -Maximum 5000)
}