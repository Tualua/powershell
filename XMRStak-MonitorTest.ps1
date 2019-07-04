Import-Module "$PSScriptRoot\PSxmrstakMonitoring.psm1" -Force

$MaxThreads = 10
$SleepTimer = 200

$BeginTime = Get-Date
$BeginTime
$ConfigPath = "$PSScriptRoot\xmrminers.json"
$Miners = Get-Miners -File $ConfigPath
$MinersInfoTable = New-Object System.Collections.ArrayList

#Get-MinerHardwareInfo -Hostname '192.168.24.205' -OSUser 'xmr' -OSPassword 'DenXiaoPing2653' -OS 'windows'


$Jobs = @()
$ISS = [initialsessionstate]::CreateDefault()
$ISS.ImportPSModule("$PSScriptRoot\PSxmrstakMonitoring.psm1")
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $ISS, $Host)
$RunspacePool.Open()

ForEach ($HashMiner in $Miners.Keys)
{
  $PowershellThread = [powershell]::Create().AddCommand('Get-MinerHardwareInfo')
  $CommandParameters = $Miners.$HashMiner.Clone()
  $CommandParameters.Remove('Customer')
  $CommandParameters.Remove('APIUser')
  $CommandParameters.Remove('APIPassword')
  $CommandParameters.Remove('APIPort')
  $CommandParameters.Remove('Wallet')
  
  $null = $PowershellThread.AddParameters($CommandParameters)
  #$null = $PowershellThread.AddParameter('Worker',$HashMiner)
  $PowershellThread.RunspacePool = $RunspacePool
  $Handle = $PowershellThread.BeginInvoke()
  $Job = '' | Select-Object Handle, Thread, Object
  $Job.Handle = $Handle
  $Job.Thread = $PowershellThread
  $Job.Object = $HashMiner
  $Jobs += $Job  
}

While (@($Jobs | Where-Object {$_.Handle -ne $Null}).count -gt 0)  
  {
    ForEach ($Job in $($Jobs | Where-Object {$_.Handle.IsCompleted -eq $True}))
    {
      $MinerInfo = $Job.Thread.EndInvoke($Job.Handle)[0]
      $MinerInfo.Worker = $Job.Object      
      $PSCMiner = [psCustomObject]$($Miners.$($Job.Object) + $MinerInfo)
      $null = $MinersInfoTable.Add($PSCMiner)
      $Job.Thread.Dispose()
      $Job.Thread = $Null
      $Job.Handle = $Null        
    }
      Start-Sleep -Milliseconds $SleepTimer
  }

$RunspacePool.Close()
$RunspacePool.Dispose()

$EndTime = Get-Date
$EndTime

$MinersInfoTable|Sort-Object -Property Customer,Worker|Format-Table -Property Customer,Worker,Hostname,OS,Threads,LocalHashrate,GPUName,GPUStatus
{0:mm:ss} -f $EndTime