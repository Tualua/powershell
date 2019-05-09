Import-Module -Name $env:windir\SharpSnmpLib.dll
Add-Type -AssemblyName SharpSnmpLib

function Get-SwitchFDBCisco
{
  param (
    [string]$IPAddress,
    [string[]]$IgnoreIf,
    [int]$MinVLAN = 1,
    [int]$MaxVLAN = 1000
  )
  $swPortRange = 48
  $dot1dTpFdbPort = '.1.3.6.1.2.1.17.4.3.1.2'
  $dot1dBasePortIfIndex = '.1.3.6.1.2.1.17.1.4.1.2'
  $vtpVlanState = '.1.3.6.1.4.1.9.9.46.1.3.1.1.2.1'
  $ifName = '.1.3.6.1.2.1.31.1.1.1.1'
  $FDB = @()
  $MACAddresses = @()
  $SleepTimer = 100
    
     
    
    $ip = [ipaddress]::Parse($IPAddress)
    $svr = New-Object System.Net.IpEndPoint ($ip, 161)
       
    $ver = [Lextm.SharpSnmpLib.VersionCode]::V2
    $walkMode = [Lextm.SharpSnmpLib.Messaging.WalkMode]::WithinSubtree
    $maxRepetitions = 10
    
    $swIfNames = New-Object 'System.Collections.Generic.List[Lextm.SharpSnmpLib.Variable]'
    $oid = New-Object Lextm.SharpSnmpLib.ObjectIdentifier ($ifName)
    try 
    {
        [Lextm.SharpSnmpLib.Messaging.Messenger]::BulkWalk($ver, $svr, 'public', $oid, $swIfNames, 10000, $maxRepetitions, $walkMode, $null, $null)|Out-Null
    } 
    catch [Lextm.SharpSnmpLib.Messaging.TimeoutException]
    {
      Write-Error "SNMP Timeout connecting to $svr"
      
    }
    catch {
       Write-Error "SNMP Walk error: $_"
       
    }
    $tableSwIfNames = @{}
      ForEach ($swIfName in $swIfNames)
      {
        $tableSwIfNames.Add($($swIfName.Id).ToString().SubString($ifName.Length),$($swIfName.Data).ToString())
      }
    
    $oid = New-Object Lextm.SharpSnmpLib.ObjectIdentifier ($vtpVlanState)
    $swVlans = New-Object 'System.Collections.Generic.List[Lextm.SharpSnmpLib.Variable]'
    try 
    {
        [Lextm.SharpSnmpLib.Messaging.Messenger]::BulkWalk($ver, $svr, 'public', $oid, $swVlans, 10000, $maxRepetitions, $walkMode, $null, $null)|Out-Null
    } 
    catch [Lextm.SharpSnmpLib.Messaging.TimeoutException]
    {
      Write-Error "SNMP Timeout connecting to $svr"
      
    }
    catch {
       Write-Error "SNMP Walk error: $_"
       
    }
    foreach ($vlan in $swVlans)
    {
      $vlanid = $($vlan.id).ToString().SubString($vtpVlanState.Length)
      
      $oid = $dot1dBasePortIfIndex
      $swMappings = New-Object 'System.Collections.Generic.List[Lextm.SharpSnmpLib.Variable]'
      try 
      {
        [Lextm.SharpSnmpLib.Messaging.Messenger]::BulkWalk($ver, $svr, $('public@',$vlanid -join ''), $oid, $swMappings, 10000, $maxRepetitions, $walkMode, $null, $null)|Out-Null
      } 
      catch [Lextm.SharpSnmpLib.Messaging.TimeoutException]
      {
        Write-Error "SNMP Timeout connecting to $svr getting info for VLAN $vlanid"
      }
      catch 
      {
        Write-Error "SNMP Walk error: $_"
      }
      $tableSwMappings = @{}
      ForEach ($mapping in $swMappings)
      {
        $tableSwMappings.Add($($mapping.Id).ToString().SubString($dot1dBasePortIfIndex.Length),$($mapping.Data).ToString())
      }
      
      Start-Sleep -Milliseconds $SleepTimer
      $vlanFDBPortTemp = New-Object 'System.Collections.Generic.List[Lextm.SharpSnmpLib.Variable]'
      $oid = $dot1dTpFdbPort
      try 
      {
        [Lextm.SharpSnmpLib.Messaging.Messenger]::BulkWalk($ver, $svr, $('public@',$vlanid -join ''), $oid, $vlanFDBPortTemp, 10000, $maxRepetitions, $walkMode, $null, $null)|Out-Null
      } 
      catch [Lextm.SharpSnmpLib.Messaging.TimeoutException]
      {
        Write-Error "SNMP Timeout connecting to $svr getting info for VLAN $vlanid"
      }
      catch 
      {
        Write-Error "SNMP Walk error: $_"
      } 
       If ($vlanFDBPortTemp.Count -gt 0)
       {
         ForEach ($FDBItem in $vlanFDBPortTemp)
         {
           $MACaddrDec = @()
           $MACAddrHex = @()
           $MACaddrDec =$($FDBItem.Id).ToString().Substring(23).Split('.')
           ForEach ($octet in $MACaddrDec)
           {
             $MacAddrHex += '{0:X2}' -f [int]$octet
           }
           $MACAddr = $MacAddrHex -join ":"
           $Interface = $tableSwIfNames[$($tableSwMappings["$($FDBItem.Data)"])]
           If ($Interface -ne $IgnoreIf)
           {
             $MACAddresses += [PSCustomObject]@{
                        macaddr = $MACAddr
                        ifNumber = $Interface
                      }
           }
         }
         
       }
  
    }
    
    
    
   return $MACAddresses
}

Get-SwitchFDBCisco -IPAddress '172.17.17.124' -IgnoreIf 'Gi1/0/4'