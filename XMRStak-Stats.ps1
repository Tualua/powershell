#XMR-Stak statistics
param (
  [string[]]$Miners = @()
)

function Get-MinersFromFile 
{
  param
  (
    [Parameter(Mandatory=$true)][string]
    $Path    
  )
  $hashMiners = @()
  $config = Get-Content -Path $Path | ConvertFrom-Json 
  ForEach ($miner in $config.miners)
  {
    $hashMiner = @{}
    foreach ($property in $miner.PSObject.Properties) 
    {
      $hashMiner[$property.Name] = $property.Value
    }
    $hashMiners += $hashMiner
    
  }  
  
  return $hashMiners #| Sort-Object -Property { [Version] $_} -Unique
}
function Get-MinerData
{
  param
  (
    [string]$user, 
    [string]$pass, 
    [string]$miner,
    [int]$minerport
  ) 
  $responseData = ''
  $apiurl = 'api.json'
  $securepasswd = ConvertTo-SecureString $pass -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential($user, $securepasswd)
  $url = $("http://$miner",$minerport -join ':'),$apiurl -join '/'
  try
  {
    $responseData = Invoke-WebRequest -Uri $url -Credential $cred -TimeoutSec 5
  }
  catch [System.Net.WebException]
  {
    Write-Verbose "An exception was caught connecting to $miner : $($_.Exception.Message)"
  }
      
  return $responseData
  }

If (!($Miners))
{
  $Miners = Get-MinersFromFile -Path $(Join-Path -Path $PSSCriptRoot -ChildPath 'xmrminers.json' )
}
 
$stats = @()
$total10s= 0
$total60s= 0
$total15m= 0
$totals = @()

ForEach ($miner in $Miners)
{
  #Write-Host ($miner['macaddr'] -replace ':')
  $rawdata = Get-MinerData -user $miner['http_user'] -pass $miner['http_user_pass'] -miner $miner['hostname'] -minerport $miner['http_port']
  If ($rawdata)
  {
    $stats += [psCustomObject]@{
        'miner' = $miner['macaddr'] -replace ':'
        'hashrate 10s' = [int]$($rawdata.content|ConvertFrom-Json).hashrate.total[0]
        'hashrate 60s' = [int]$($rawdata.content|ConvertFrom-Json).hashrate.total[1]
        'hashrate 15m' = [int]$($rawdata.content|ConvertFrom-Json).hashrate.total[2]
        'threads' = [int]$($rawdata.content|ConvertFrom-Json).hashrate.threads.count
      
    }
    $total10s += [int]$($rawdata.content|ConvertFrom-Json).hashrate.total[0] 
    $total60s += [int]$($rawdata.content|ConvertFrom-Json).hashrate.total[1] 
    $total15m += [int]$($rawdata.content|ConvertFrom-Json).hashrate.total[2] 
  }
  Else
  {
    $stats += [psCustomObject]@{
        'miner' = $miner['macaddr'] -replace ':'
        'hashrate 10s' = 0
        'hashrate 60s' = 0
        'hashrate 15m' = 0
        'threads' = 0
    }
  }
}

$stats.GetEnumerator()|Sort-Object -Property 'hashrate 15m' -Descending | Format-Table
#$stats| Format-Table
Write-Host $("Total miners:", $stats.Count -join ' ')


$totals += [psCustomObject]@{
      'data' = 'Total'
      'hashrate 10s' = $total10s
      'hashrate 60s' = $total60s
      'hashrate 15m' = $total15m
      
      
  }
$totals += [psCustomObject]@{
      'data' = 'Average'
      'hashrate 10s' = [int]$($total10s/($stats.Count-1))
      'hashrate 60s' = [int]$($total60s/($stats.Count-1))
      'hashrate 15m' = [int]$($total15m/($stats.Count-1))
      
      
  }
$totals | Format-Table

#Write-Host -NoNewLine 'Press any key to continue...';
#$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
