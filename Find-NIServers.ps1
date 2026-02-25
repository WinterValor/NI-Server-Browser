param(
  [string]$MasterUrl = 'http://warbandmain.taleworlds.com/handlerservers.ashx?type=list',
  [int]$TimeoutSec = 30,
  [int]$ThrottleLimit = 64,
  [int]$MaxEndpoints = 0,   # 0 = scan all
  [switch]$OnlyEU
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-MasterListText {
  param([string]$Url)

  try {
    return (Invoke-WebRequest -Uri $Url -TimeoutSec 15).Content
  } catch {
    # Fallback to https if http fails (master list only)
    $https = $Url -replace '^http://', 'https://'
    return (Invoke-WebRequest -Uri $https -TimeoutSec 15).Content
  }
}

function Normalize-Endpoints {
  param([string]$MasterText)

  $raw = $MasterText -split '\|' | ForEach-Object { $_.Trim() } | Where-Object { $_ }

  $raw | ForEach-Object {
    if ($_ -match '^\d{1,3}(\.\d{1,3}){3}:\d+$') { $_ }
    elseif ($_ -match '^\d{1,3}(\.\d{1,3}){3}$') { "$_:7240" }  # default port if missing
    else { $null }
  } | Where-Object { $_ }
}

# 1) Fetch master list
$masterText = Get-MasterListText -Url $MasterUrl

# 2) Parse endpoints
$endpoints = Normalize-Endpoints -MasterText $masterText

# 3) Optional: prioritize IPs that host many ports (often finds big clusters faster)
$endpoints = $endpoints |
  Group-Object { ($_ -split ':')[0] } |
  Sort-Object Count -Descending |
  ForEach-Object { $_.Group }

if ($MaxEndpoints -gt 0) {
  $endpoints = $endpoints | Select-Object -First $MaxEndpoints
}

Write-Host ("Probing {0} endpoints (Throttle={1}, Timeout={2}s)..." -f ($endpoints.Count), $ThrottleLimit, $TimeoutSec)

# 4) Probe in parallel (PS7+)
$results = $endpoints | ForEach-Object -Parallel {
    $endpoint = $_
    $uri = "http://$endpoint/"

    try {
        $resp = Invoke-WebRequest -Uri $uri -TimeoutSec $using:TimeoutSec -ErrorAction Stop
        $xml  = [xml]$resp.Content

        $nameNode = $xml.SelectSingleNode('//Name')
        if (-not $nameNode) { return }

        $name = $nameNode.InnerText
        if (-not $name.StartsWith('NI_')) { return }
        if ($using:OnlyEU.IsPresent -and ($name -notmatch '^NI_EU_')) { return }

        $mapNode     = $xml.SelectSingleNode('//MapName')
        $playersNode = $xml.SelectSingleNode('//NumberOfActivePlayers')
        $maxNode     = $xml.SelectSingleNode('//MaxNumberOfPlayers')

        [pscustomobject]@{
            Name       = $name
            Endpoint   = $endpoint
            Map        = if ($mapNode) { $mapNode.InnerText } else { $null }
            Players    = if ($playersNode) { $playersNode.InnerText } else { $null }
            MaxPlayers = if ($maxNode) { $maxNode.InnerText } else { $null }
        }
    } catch {
        return
    }
} -ThrottleLimit $ThrottleLimit

# 5) Output: list of NI_* servers
if (-not $results) {
  Write-Host "No NI_* servers found via HTTP XML probe." -ForegroundColor Yellow
  exit 0
}

$results |
  Sort-Object Name -Unique |
  Format-Table -AutoSize Name, Endpoint, Players, MaxPlayers, Map