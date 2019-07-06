#Module with functions relatd to xmrstak monitoring
Function Get-Miners
{
  param(
    [Parameter(Mandatory=$true)][string]$File
  )
  If (Test-Path -Path $File)
  {
    $Config = Get-Content -Path $File | ConvertFrom-Json 
    #$Miners = New-Object System.Collections.ArrayList
    $Miners = @{}
    ForEach ($RecordCustomer in $Config.customers)
    {
      ForEach ($RecordMiner in $RecordCustomer.miners)
      {
        $Miner = @{}
        $Miner.Customer = $RecordCustomer.name
        $Miner.OS = $RecordMiner.os
        $Miner.OSUser = $RecordMiner.osuser
        $Miner.OSPassword = $RecordMiner.ospassword
        $Miner.Hostname = $RecordMiner.hostname
        $Miner.APIUser = $RecordMiner.apiuser
        $Miner.APIPassword = $RecordMiner.apipassword
        $Miner.APIPort = $RecordMiner.APIPort
        $Miner.Wallet = $RecordCustomer.wallet          
        $Miners.Add($($RecordMiner.macaddr -replace ':'), $Miner)
      }      
    }
  }  
  
  return $Miners
}
function Get-XMRStakStats
{
  param(
    [Parameter(Mandatory=$true)][string]$Hostname,
    [Parameter(Mandatory=$true)][string]$APIUser,
    [Parameter(Mandatory=$true)][string]$APIPassword,
    [Parameter(Mandatory=$true)][string]$APIPort    
  )
  $xmrstakdata = ''
  $Result = @{}
  $Result.LocalStatus = 'Error'
  $Result.LocalHashrate = 0
  $Result.Threads = 0
  
  $APIUrl = 'api.json'
  $Cred = New-Object System.Management.Automation.PSCredential($APIUser, $(ConvertTo-SecureString $APIPassword -AsPlainText -Force))
  $url = ('http://',$($Hostname, $APIPort -join ':') -join ''),$APIurl -join '/'
  try
  {
    $xmrstakdata = Invoke-RestMethod -Uri $url -Credential $cred -TimeoutSec 5   
  }
  catch [Net.WebException]
  {
    Write-Verbose "An exception was caught connecting to $Hostname : $($_.Exception.Message)"
    $xmrstakdata = @()
    
  }
  If ($xmrstakdata)
  {
    $Result.Threads = $xmrstakData.hashrate.threads.count
    [double]$HashrateByThreads = 0
    ForEach ($Thread in $xmrstakData.hashrate.threads)
    {
      $HashrateByThreads += $Thread[0]
    } 
    If ($xmrstakdata.hashrate.total[2])
    {
      $Result.LocalStatus = 'OK'
      $Result.LocalHashrate = $xmrstakdata.hashrate.total[2]      
    }
    Else
    {
      $Result.LocalStatus = 'Warning'
      $Result.LocalHashrate = $HashrateByThreads
    }    
  }
  Else
  {
    
  }
  
  Return $Result
}

function Get-MinerPoolStats
{
  param(  
    [Parameter(Mandatory=$true)][string]$Worker,
    [Parameter(Mandatory=$true)][string]$Wallet
  )
  $ResponseData = ''
  $PoolAPIUrl = "https://www.supportxmr.com/api/miner/$Wallet/stats/$Worker"
  Try
  {
    $ResponseData = Invoke-RESTMethod -Uri $PoolAPIUrl -TimeoutSec 10
  }
  Catch [Net.WebException]
  {
    Write-Verbose "An exception was caught connecting to pool : $($_.Exception.Message)"
  }
      
  return $ResponseData.hash
  
}

Function Get-MinerHardwareInfo
{
  param(
    [Parameter(Mandatory=$true)][string]$Hostname,
    [Parameter(Mandatory=$true)][string]$OSUser,
    [Parameter(Mandatory=$true)][string]$OSPassword,
    [Parameter(Mandatory=$true)][string]$OS
  )
  $GPUStatus = @{}
  $PasswordSecure  = ConvertTo-SecureString -AsPlainText -String $OSPassword -Force
  $Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $OSUser,$PasswordSecure
  If ($OS -eq 'windows')
  {
    $PSSession = New-PSSession -ComputerName $Hostname -Credential $Cred
    $GPUInfo = Invoke-Command -Session $PSSession -ScriptBlock { Get-WmiObject Win32_VideoController }
    If ($GPUInfo)
    {
      $GPUStatus.GPUPresent = $true
      $GPUStatus.GPUName = $GPUInfo.Name
      $GPUStatus.GPUStatus = $GPUInfo.Status
    }
    Else
    {
      $GPUStatus.GPUPresent = $false
      $GPUStatus.GPUName = 'None'
      $GPUStatus.GPUStatus = 'None'
    }
  }
  ElseIf ($OS -eq 'linux')
  {
    $PasswordSecure  = ConvertTo-SecureString -AsPlainText -String $OSPassword -Force
    $Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $OSUser,$PasswordSecure
    $o = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
    $Result = Invoke-Command -ComputerName $Hostname -Credential $cred -UseSSL -Authentication Basic -SessionOption $o -ScriptBlock {
      Invoke-Expression -Command 'lshw -class display|grep product'   
  
    } -ErrorAction SilentlyContinue -ErrorVariable err
    
    If ($Result)
    {
      $GPUStatus.GPUPresent = $true
      $GPUStatus.GPUName = $($Result.Split(':'))[1].Trim()
      $GPUStatus.GPUStatus = 'N/A'
    }
    Else
    {
      $GPUStatus.GPUPresent = $false
      $GPUStatus.GPUName = 'None'
      $GPUStatus.GPUStatus = 'None'
    }        
  }
  Else
  {
    $GPUStatus.GPUPresent = $false
    $GPUStatus.GPUName = 'Unable to detect'
    $GPUStatus.GPUStatus = 'Unsupported OS'
  }
  Return $GPUStatus
}

Function Get-MinerDataAll
{
  param(
    [Parameter(Mandatory=$true)][string]$Hostname,
    [Parameter(Mandatory=$true)][string]$OS,
    [Parameter(Mandatory=$true)][string]$OSUsername,
    [Parameter(Mandatory=$true)][string]$OSPassword,
    [Parameter(Mandatory=$true)][string]$APIUser,
    [Parameter(Mandatory=$true)][string]$APIPassword,
    [Parameter(Mandatory=$true)][string]$APIPort,
    [Parameter(Mandatory=$true)][string]$Worker,
    [Parameter(Mandatory=$true)][string]$Wallet
  )
  $MinerInfo = @{}
  
  $LocalHashrate = Get-XMRStakStats -Hostname $Hostname -APIUser $APIUser -APIPassword $APIPassword -APIPort $APIPort
  $MinerInfo += $LocalHashrate
    
  $MinerInfo.PoolHashrate = Get-MinerPoolStats -Worker $Worker -Wallet $Wallet
  If ($MinerInfo.PoolHashrate -eq 0)
  {
    $MinerInfo.PoolStatus = 'Missing'
  }
  Else
  {
    $MinerInfo.PoolStatus = 'OK'
  }
  
  Return $MinerInfo
}

function Get-PowerReadingDCMI
{
  param(
    [Parameter(Mandatory=$true)][string]$BMC,
    [Parameter(Mandatory=$true)][string]$BMCUser,
    [Parameter(Mandatory=$true)][string]$BMCPassword
  )
}

Function Restart-OS
{
  param (
    [Parameter(Mandatory=$true)][string]$Hostname,
    [Parameter(Mandatory=$true)][string]$Username,
    [Parameter(Mandatory=$true)][string]$Password,
    [Parameter(Mandatory=$true)][string]$OS
  )
  
  $PasswordSecure  = ConvertTo-SecureString -AsPlainText -String $Password -Force
  $Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username,$PasswordSecure
  $Result = ''
  If ($OS -eq 'linux')
  {
    $o = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck  
    Invoke-Command -ComputerName $Hostname -Credential $cred -UseSSL -Authentication Basic -SessionOption $o -ScriptBlock {
      Invoke-Expression -Command '/sbin/shutdown -t +1 -r'   
    } -ErrorAction SilentlyContinue -ErrorVariable err
    
    switch ($err[0].Exception.GetType().FullName)
    {
      'System.Management.Automation.Remoting.PSRemotingTransportException' {return 'Failed'}
      'System.Management.Automation.RemoteException' {
        If ($err[0].Exception.ErrorRecord -like 'Shutdown scheduled*')
        {
          $result = 'Scheduled'
        }
        Else
        {
          $result = $err[0].Exception.ErrorRecord
        }
      }
      default {$result = 'Unknown'}
    }  
  }
  ElseIf ($OS -eq 'windows')
  {
    Try
    {
      $Session = New-PSSession -ComputerName $Hostname -Credential $Cred -ErrorAction Stop
    }
    Catch
    {
      Write-Error "Unable to connect to $Hostname" 
      $result = 'Failed'
    }
    Finally
    {
      If ($Session)
      {
        $result = Invoke-Command -Session $Session -ScriptBlock {
          Restart-Computer -Force      
        }
      }
    }
  }
  Else
  {
    $Result = 'Unknown OS Type'
  }
  
  return $Result
}
