# The caller supplies an owner hash and VMnet numbers, never credentials.
$ErrorActionPreference = 'Stop'
$root = 'HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.\VMnetLib\VMnetConfig'
$segments = 'HKLM:\SYSTEM\CurrentControlSet\Services\VMnetDHCP\Parameters\VirtualEthernetSegments'
$adapters = @(Get-NetAdapter -IncludeHidden)
$routes = @(Get-NetRoute -AddressFamily IPv4 | Select-Object -ExpandProperty DestinationPrefix -Unique)
$natParams = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\VMware NAT Service\Parameters' -ErrorAction Stop
$natConfig = Get-Content -LiteralPath (Join-Path ([Environment]::ExpandEnvironmentVariables($natParams.ConfigPath)) 'vmnetnat.conf')
$natDevices = @($natConfig | ForEach-Object { if ($_ -match '^\s*device\s*=\s*(vmnet\d+)\s*(?:[#;].*)?$') { $Matches[1] } })
if ($natDevices.Count -ne 1) { throw 'Cannot verify VMware NAT device' }
function HasHostPort($name) {
    $pattern = '(?i)\b' + [regex]::Escape($name) + '(?: #\d+)?$'
    return @($adapters | Where-Object { $_.InterfaceDescription -match $pattern }).Count -gt 0
}
$ids = @(2..19 | Where-Object { $_ -ne 8 })
$owned = @($ids | Where-Object { (Get-ItemProperty -LiteralPath "$root\vmnet$_" -Name GuestGateOwner -ErrorAction SilentlyContinue).GuestGateOwner -eq $owner })
if ($audit -and $owned.Count -ne 1) { throw "Cannot verify ownership of private network" }
if ($owned.Count -gt 1) { throw 'Multiple isolated networks claim this VM' }
if ($owned.Count -eq 1) { $id = $owned[0] } else {
    $id = 0
    foreach ($n in $ids) {
        $name = "vmnet$n"
        if ($name -in $occupied -or $name -in $listed -or $name -in $natDevices -or (HasHostPort $name) -or (Test-Path "$segments\$n")) { continue }
        if (Test-Path "$root\$name") {
            $entry = Get-Item "$root\$name"
            if (@($entry.Property | Where-Object { $_ -ne 'DisplayName' }).Count -or @(Get-ChildItem $entry.PSPath).Count) { continue }
            if ($entry.GetValue('DisplayName', $name) -ne $name) { continue }
        }
        $id = $n
        break
    }
    if (!$id) { throw 'No unused VMware custom network available' }
}
$name = "vmnet$id"
$key = "$root\$name"
$seg = "$segments\$id"
# Reject an explicit VMware bridge mapping even on an adapterless network.
$bridge = 'HKLM:\SYSTEM\CurrentControlSet\Services\VMnetBridge\Parameters\Adapters'
if (Test-Path $bridge) {
    foreach ($b in @((Get-Item $bridge)) + @(Get-ChildItem $bridge -Recurse)) {
        foreach ($prop in $b.Property) {
            $value = $b.GetValue($prop)
            if ($value -eq $name -or ($prop -match '^(Vnet|VMnet|VirtualEthernetSegment)$' -and $value -eq $id)) { throw "VMware bridge configuration references $name" }
        }
    }
}
if (!$audit -and $owned.Count -and (Get-ItemProperty $key -Name GuestGateStaging -ErrorAction SilentlyContinue).GuestGateStaging -eq 1) {
    if ($name -in $occupied -or $name -in $natDevices) { throw "Unexpected user of staged network $name" }
    if (HasHostPort $name) {
        $ctl = Join-Path (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation').InstallPath 'vnetlib64.exe'
        Start-Process -FilePath $ctl -ArgumentList @('--','remove','adapter',$name) -Wait -WindowStyle Hidden
        $adapters = @(Get-NetAdapter -IncludeHidden)
        if (HasHostPort $name) {throw "Could not remove interrupted staging adapter $name"}
        throw "Recovered staging adapter for $name; retry after VMware refreshes its inventory"
    }
    Remove-ItemProperty $key -Name GuestGateStaging
}
if ($name -in $occupied -or $name -in $natDevices -or (HasHostPort $name) -or $name -in $listed) { throw "Isolation check failed for $name (peer, host adapter, bridge or external network)" }
# Exclude routed subnets and DHCP scopes belonging to other networks.
function IpNumber([string]$ip) {
    $b = ([Net.IPAddress]::Parse($ip)).GetAddressBytes()
    [Array]::Reverse($b)
    return [BitConverter]::ToUInt32($b,0)
}
$ranges = @(
    foreach ($route in $routes) {
        $r = $route.Split('/')
        if ([int]$r[1] -gt 0) {
            $first = IpNumber $r[0]
            ,@([long]$first, ([long]$first + [long][Math]::Pow(2,32-[int]$r[1])-1))
        }
    }
)
$dhcpFile = Join-Path $env:ProgramData 'VMware/vmnetdhcp.conf'
$config = [IO.File]::ReadAllText($dhcpFile)
$ownPrefix = (Get-ItemProperty $key -Name IPSubnetAddress -ErrorAction SilentlyContinue).IPSubnetAddress
foreach ($scope in [regex]::Matches($config,'(?im)^\s*subnet\s+([.0-9]+)\s+netmask\s+([.0-9]+)')) {
    if ($owned.Count -and $ownPrefix -eq $scope.Groups[1].Value -and $config.Contains("# GuestGate isolated $owner")) {continue}
    $start = IpNumber $scope.Groups[1].Value
    $ranges += ,@([long]$start,([long]$start + 4294967295L - (IpNumber $scope.Groups[2].Value)))
}
function AvailableSubnet([string]$ip) {
    if ($ip -notmatch '^172\.(2[6789]|30)\.\d{1,3}\.0$') { return $false }
    $first = IpNumber $ip
    foreach ($r in $ranges) {if ($first -le $r[1] -and ($first + 255) -ge $r[0]) {return $false}}
    return $true
}
if (!$owned.Count) {
    if (!(Test-Path $key)) { New-Item $key | Out-Null }
    New-ItemProperty $key -Name GuestGateOwner -Value $owner -PropertyType String | Out-Null
}
$k = Get-Item $key
if (@($k.Property | Where-Object {$_ -notin @('DisplayName','GuestGateOwner','IPSubnetAddress','IPSubnetMask')}).Count) { throw "Unexpected VMware configuration for $name" }
if (@(Get-ChildItem $key | Where-Object {$_.PSChildName -notin @('Adapter','DHCP')}).Count) { throw "Unexpected VMware binding for $name" }
if (Test-Path "$key\Adapter") {
    $a = Get-ItemProperty "$key\Adapter"
    if ($a.UseAdapter -ne 0 -or $a.AdapterInstalled -ne 0) { throw "Host virtual adapter configured on $name" }
}
$subnet = $k.GetValue('IPSubnetAddress')
if (!$subnet) {
    if($audit){throw "Missing isolated subnet"}
    $subnet = $(foreach ($b in 26..30) { foreach ($c in 1..254) {
        $ip = "172.$b.$c.0"; if (AvailableSubnet $ip) { $ip; break }
    }}) | Select-Object -First 1
    if (!$subnet) { throw 'No free isolated subnet' }
    New-ItemProperty $key -Name IPSubnetAddress -Value $subnet -PropertyType String | Out-Null
}
if (!(AvailableSubnet $subnet)) { throw "Isolated subnet overlaps an existing network or route: $subnet" }
if ($k.GetValue('IPSubnetMask','255.255.255.0') -ne '255.255.255.0') { throw 'Unexpected isolated subnet mask' }
if ($audit -and (!(Test-Path "$key\DHCP") -or !(Test-Path "$key\Adapter") -or !(Test-Path $seg))) { throw "Incomplete private network configuration" }
if (!(Test-Path "$key\DHCP")) { New-Item "$key\DHCP" | Out-Null }
if (!(Test-Path $seg)) { New-Item $seg | Out-Null }
$hostAddr = $subnet -replace '\.0$','.1'
$num = [BitConverter]::ToUInt32(([Net.IPAddress]::Parse($hostAddr)).GetAddressBytes(),0)
function RequireValue($path,$field,$value,$type) {
    $entry = Get-Item $path
    if ($field -in $entry.Property) {
        if ($entry.GetValue($field) -ne $value) { throw "Unexpected $field on $name" }
    } else { if ($audit){throw "Missing $field on $name"}; New-ItemProperty $path -Name $field -Value $value -PropertyType $type | Out-Null }
}
if (!(Test-Path "$key\Adapter")) { New-Item "$key\Adapter" | Out-Null }
RequireValue "$key\Adapter" 'UseAdapter' 0 'DWord'
RequireValue "$key\Adapter" 'AdapterInstalled' 0 'DWord'
RequireValue $key 'IPSubnetMask' '255.255.255.0' 'String'
RequireValue "$key\DHCP" 'UseDHCP' 1 'DWord'
RequireValue $seg 'HostIpAddress' $num 'DWord'
RequireValue $seg 'ListenTo' 1 'DWord'
[pscustomobject]@{Network=$name;Subnet=$subnet} | ConvertTo-Json -Compress
