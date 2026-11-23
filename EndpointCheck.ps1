<#
  Windows Endpoint Check - FULL SYSTEM REPORT  (READ-ONLY)
  - It only READS information. It changes NO Windows setting.
  - 65 checks in 12 groups. Every check ends as GOOD or BAD (or NOT CHECKED if Windows would not give the data).
  - It saves a PDF report (every issue as Critical / High / Medium / Low, each with its proof) and an HTML copy in the same folder as this script.
  - A check that cannot be proven is listed as NOT CHECKED (never guessed as BAD).
  - It takes about 3 to 6 minutes. Do not close the window.
  - Run:  powershell -ExecutionPolicy Bypass -File .\EndpointCheck.ps1
  - Use only on systems you are authorized to assess.
#>

# ===== SETTINGS YOU CAN EDIT (optional) =====================================
$ApprovedAdmins      = @()    # approved extra admins, e.g. 'PC01\john'
$ApprovedSoftware    = @()    # risky software the client approved, e.g. 'utorrent'
$ApprovedShares      = @()    # shares the client approved, e.g. 'Data'
$ApprovedRemoteTools = @()    # remote tools the client approved, e.g. 'AnyDesk'
$RequireUsbBlocked   = $true  # set $false if the client allows USB storage
$CheckOnline         = $true  # set $false to skip the 2 checks that need internet (pending updates, outdated apps)
$ProxyAllowed        = $false # set $true if the client uses a proxy server
$ClientName          = ''     # optional client name. Empty = the cover shows only the PC's IP address
$PreparedBy          = 'Your Company Name'
$ShowLogo            = $false # set $true to show the company logo on the cover
$Classification      = 'Confidential'
$DevicePrefix        = ''     # issue ID prefix, e.g. 'MRT' gives MRT-01. Empty = made from the computer name
# =============================================================================

$ErrorActionPreference = 'SilentlyContinue'
$TotalChecks = 65

# ---------- Step 0: make sure we run as Administrator ----------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    if (-not $PSCommandPath) {
        Write-Host 'Please open PowerShell as Administrator (right-click > Run as administrator) and run this again.' -ForegroundColor Red
        return
    }
    Write-Host 'Not Administrator. Asking Windows to restart this script as Administrator...' -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath)
    exit
}

# ---------- Ask which system this is (shown on the report) ----------
$SystemLabel = ''
try {
    Write-Host ''
    Write-Host 'Which system is this? Type a short name, for example: Front Office, Reception, Doctor Cabin 2, Accounts PC' -ForegroundColor Cyan
    $SystemLabel = ([string](Read-Host 'System name (press Enter to skip)')).Trim()
} catch { $SystemLabel = '' }
$SystemLabel = ($SystemLabel -replace '[\x00-\x1F]', '')
if ($SystemLabel.Length -gt 60) { $SystemLabel = $SystemLabel.Substring(0, 60) }
$labelFile = (($SystemLabel -replace '[^A-Za-z0-9]+', '_').Trim('_'))
if ($labelFile) { $labelFile = $labelFile + '_' }

# ---------- Where to save the report ----------
$outDir = if ($PSScriptRoot) { $PSScriptRoot } else { [Environment]::GetFolderPath('Desktop') }
try {
    $t = Join-Path $outDir '.writetest'
    Set-Content -Path $t -Value 'x' -ErrorAction Stop
    Remove-Item $t -Force
} catch {
    $outDir = [Environment]::GetFolderPath('Desktop')
}
$base = Join-Path $outDir ('EndpointReport_{0}{1}_{2}' -f $labelFile, $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmm'))
$html = $base + '.html'
$pdf  = $base + '.pdf'

# ---------- Helpers ----------
$script:results = New-Object System.Collections.ArrayList
$script:cat = ''

function Enc { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }

function Fmt {
    param($Obj, [switch]$List, [string]$Empty = '(no output)')
    if ($null -eq $Obj -or @($Obj).Count -eq 0) { return $Empty }
    if ($List) { $t = $Obj | Format-List | Out-String -Width 120 }
    else       { $t = $Obj | Format-Table -AutoSize -Wrap | Out-String -Width 120 }
    return $t.Trim()
}

function RegVal {
    param([string]$Path, [string]$Name)
    $o = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    if ($o) { return $o.$Name }
    return $null
}

function Test-UserWritable {
    param([string]$Path)
    $acl = Get-Acl -Path $Path -ErrorAction SilentlyContinue
    if (-not $acl) { return $false }
    foreach ($ace in $acl.Access) {
        if (([string]$ace.AccessControlType -eq 'Allow') -and ([string]$ace.PropagationFlags -notmatch 'InheritOnly') -and ([string]$ace.IdentityReference -match '\\Users$|Everyone|Authenticated Users') -and ([string]$ace.FileSystemRights -match 'FullControl|Modify|Write|CreateFiles|AppendData|ChangePermissions|TakeOwnership')) { return $true }
    }
    return $false
}

function Get-ExeOf {
    param([string]$Cmd)
    $c = ([string]$Cmd).Trim()
    if (-not $c) { return '' }
    if ($c.StartsWith('"')) {
        $i = $c.IndexOf('"', 1)
        if ($i -gt 0) { return $c.Substring(1, $i - 1) }
        return $c.Trim('"')
    }
    $m = [regex]::Match($c, '^(.*?\.(exe|bat|cmd|com|scr|vbs|js|ps1))(\s|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

function Test-CanCreateFile {
    param([string]$Path)
    $acl = Get-Acl -Path $Path -ErrorAction SilentlyContinue
    if (-not $acl) { return $false }
    foreach ($ace in $acl.Access) {
        if (([string]$ace.AccessControlType -eq 'Allow') -and ([string]$ace.PropagationFlags -notmatch 'InheritOnly') -and ([string]$ace.IdentityReference -match '\\Users$|^Everyone$|Authenticated Users') -and ([string]$ace.FileSystemRights -match 'FullControl|Modify|WriteData|CreateFiles|(^|, )Write(,|$)')) { return $true }
    }
    return $false
}

function Get-SignInfo {
    param([string]$Exe)
    $p = [Environment]::ExpandEnvironmentVariables([string]$Exe)
    if ((-not $p) -or (-not (Test-Path -LiteralPath $p -PathType Leaf))) { return [pscustomobject]@{ State = 'missing'; Signer = '' } }
    $sg = Get-AuthenticodeSignature -FilePath $p
    $who = ''
    if ($sg.SignerCertificate) { $who = (([string]$sg.SignerCertificate.Subject -split ',')[0] -replace '^CN=', '').Trim('"') }
    if ([string]$sg.Status -eq 'Valid') { return [pscustomobject]@{ State = 'signed'; Signer = $who } }
    return [pscustomobject]@{ State = 'unsigned'; Signer = $who }
}

function Add-Check {
    param([int]$Num, [string]$Name, [string]$Status, [string]$Finding, [string]$Output, [string]$Sev = '', [string]$Fix = '', [string]$Poc = '')
    if ($Status -eq 'BAD' -and -not $Sev) { $Sev = 'Medium' }
    [void]$script:results.Add([pscustomobject]@{
        Num = $Num; Cat = $script:cat; Name = $Name; Status = $Status; Cls = ($Status -replace ' ', '')
        Finding = $Finding; Output = $Output; Sev = $Sev; Fix = $Fix; Poc = $Poc
    })
}

function Invoke-Check {
    param([int]$Num, [string]$Name, [scriptblock]$Block)
    Write-Host ('[{0}/{1}] {2}' -f $Num, $TotalChecks, $Name)
    try { & $Block }
    catch { Add-Check $Num $Name 'NOT CHECKED' 'This check could not run.' $_.Exception.Message }
}

# ---------- Device info ----------
$cs    = Get-CimInstance Win32_ComputerSystem
$bios  = Get-CimInstance Win32_BIOS
$osAll = Get-CimInstance Win32_OperatingSystem
if ($cs.PartOfDomain) { $domainText = 'Domain: ' + $cs.Domain } else { $domainText = 'Workgroup: ' + $cs.Workgroup }
$ipCfg = @(Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' -and $_.IPv4Address })
$ipReal = @($ipCfg | Where-Object { $_.IPv4DefaultGateway })
if ($ipReal.Count -eq 0) { $ipReal = @($ipCfg | Where-Object { $_.InterfaceDescription -notmatch 'Virtual|Hyper-V|VMware|VirtualBox|Loopback|Bluetooth|TAP-|Npcap|WAN Miniport|Wi-Fi Direct|Pseudo' }) }
$ips = ((@($ipReal | ForEach-Object { @($_.IPv4Address) | ForEach-Object { [string]$_.IPAddress } }) | Where-Object { $_ -and ($_ -notmatch '^127\.|^169\.254\.') } | Select-Object -Unique) -join ', ')
if (-not $ips) { $ips = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^127\.|^169\.254\.' } | ForEach-Object { $_.IPAddress }) -join ', ' }
$dateText = Get-Date -Format 'dd MMM yyyy HH:mm'

# ---------- Data used by several checks ----------
$localUsers = Get-LocalUser

$swPaths = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
           'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
           'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
$sw = Get-ItemProperty $swPaths | Where-Object { $_.DisplayName } | Sort-Object DisplayName -Unique

# Security policy (export to a temp file, read it, delete it)
$secTxt = @()
$cfgFile = Join-Path $env:TEMP ('secpol_' + [guid]::NewGuid().ToString('N') + '.inf')
secedit /export /cfg $cfgFile /quiet | Out-Null
if (Test-Path $cfgFile) { $secTxt = Get-Content $cfgFile; Remove-Item $cfgFile -Force }
function Get-SecVal {
    param([string]$Key)
    $l = $secTxt | Where-Object { $_ -match ('^\s*' + $Key + '\s*=') } | Select-Object -First 1
    if ($l) { return (($l -split '=', 2)[1]).Trim() }
    return $null
}

$mpStatus = Get-MpComputerStatus
$mpPref   = Get-MpPreference

Write-Host ''
Write-Host "Running $TotalChecks checks on $($env:COMPUTERNAME). This takes a few minutes ..." -ForegroundColor Cyan

# =============================================================================
# GROUP A - System and Updates
# =============================================================================
$script:cat = 'System and Updates'

Invoke-Check 1 'Windows version and support' {
    $os = $osAll
    $cap = [string]$os.Caption
    $build = [int]$os.BuildNumber
    $now = Get-Date
    $edId = [string](RegVal 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'EditionID')
    $isLtsc = ($edId -match 'EnterpriseS|IoTEnterpriseS') -or ($cap -match 'LTSC|LTSB')
    $isEntEdu = ($edId -match '^(Enterprise|EnterpriseN|Education|EducationN|IoTEnterprise|ServerRdsh)$')
    $out = Fmt ($os | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime) -List
    $out += "`n`nEdition ID: $edId"
    # Windows 11 end-of-servicing dates by build: Home/Pro date, Enterprise/Education date
    $w11 = @{
        22000 = @('2023-10-10', '2024-10-08')
        22621 = @('2024-10-08', '2025-10-14')
        22631 = @('2025-11-11', '2026-11-10')
        26100 = @('2026-10-13', '2027-10-12')
        26200 = @('2027-10-12', '2028-10-10')
    }
    if ($cap -match 'Windows (7|8|Vista|XP)|Server 2003|Server 2008|Server 2012') {
        Add-Check $Num $Name 'BAD' 'This Windows version is out of support.' $out 'Critical' 'Upgrade to a supported Windows version.'
    } elseif ($cap -match 'Windows 10') {
        $ltscEnd = $null
        if ($isLtsc) {
            if ($build -eq 17763) { $ltscEnd = [datetime]'2029-01-09' }
            elseif ($build -eq 19044 -and $edId -match 'IoTEnterpriseS') { $ltscEnd = [datetime]'2032-01-13' }
            elseif ($build -eq 19044) { $ltscEnd = [datetime]'2027-01-12' }
            elseif ($build -eq 14393) { $ltscEnd = [datetime]'2026-10-13' }
            elseif ($build -eq 10240) { $ltscEnd = [datetime]'2025-10-14' }
        }
        if ($isLtsc -and $ltscEnd) {
            $out += "`nSupport for this LTSC/LTSB release ends: " + $ltscEnd.ToString('dd MMM yyyy')
            if ($now -lt $ltscEnd) {
                Add-Check $Num $Name 'GOOD' ('Windows 10 LTSC/LTSB is still supported until ' + $ltscEnd.ToString('dd MMM yyyy') + '.') $out
            } else {
                Add-Check $Num $Name 'BAD' ('This Windows 10 LTSC/LTSB release is out of support (ended ' + $ltscEnd.ToString('dd MMM yyyy') + ').') $out 'High' 'Upgrade to a supported Windows version.'
            }
        } elseif ($isLtsc) {
            Add-Check $Num $Name 'NOT CHECKED' 'Windows 10 LTSC/LTSB build is not in the script list, so support could not be decided.' $out
        } else {
            $esu = @(Get-CimInstance SoftwareLicensingProduct | Where-Object { ($_.Name -match 'ESU') -or ($_.Description -match 'ESU') })
            $esuOk = @($esu | Where-Object { $_.LicenseStatus -eq 1 })
            $postEos = @(Get-HotFix | Where-Object { $_.InstalledOn -and ([string]$_.Description -match 'Security Update') -and ($_.InstalledOn -gt [datetime]'2025-10-20') } | Sort-Object InstalledOn -Descending)
            $recent = @($postEos | Where-Object { $_.InstalledOn -gt $now.AddDays(-75) })
            $out += "`n`nESU licenses found: " + $esu.Count + "   Active: " + $esuOk.Count
            $out += "`nSecurity updates installed after Windows 10 support ended (14 Oct 2025): " + $postEos.Count
            if ($postEos.Count -gt 0) { $out += "   (latest: " + $postEos[0].HotFixID + " on " + $postEos[0].InstalledOn.ToString('dd MMM yyyy') + ")" }
            if ($esuOk.Count -gt 0) {
                Add-Check $Num $Name 'GOOD' 'Windows 10 support ended on 14 Oct 2025, but an active ESU license was found.' $out
            } elseif ($recent.Count -gt 0) {
                Add-Check $Num $Name 'GOOD' 'Windows 10 support ended on 14 Oct 2025, but security updates are still being installed, so Extended Security Updates (ESU) appear to be active.' $out
            } else {
                Add-Check $Num $Name 'BAD' 'Windows 10 support ended on 14 Oct 2025. No active ESU license was found and no security update has been installed in the last 75 days, so this PC is not getting security fixes.' $out 'High' 'Upgrade to Windows 11, or enrol the PC in Extended Security Updates (ESU).'
            }
        }
    } elseif ($cap -match 'Windows 11') {
        if ($isLtsc) {
            if ($build -eq 26100) {
                Add-Check $Num $Name 'GOOD' 'Windows 11 Enterprise LTSC 2024 is supported until 09 Oct 2029 (IoT LTSC: 2034).' $out
            } else {
                Add-Check $Num $Name 'NOT CHECKED' 'Windows 11 LTSC build is not in the script list, so support could not be decided.' $out
            }
        } elseif ($w11.ContainsKey($build)) {
            $grp = 'Home/Pro'; $ix = 0
            if ($isEntEdu) { $grp = 'Enterprise/Education'; $ix = 1 }
            $end = [datetime]($w11[$build][$ix])
            $endTxt = $end.ToString('dd MMM yyyy')
            $out += "`n`nSupport for this version ($grp) ends: $endTxt"
            if ($now -ge $end) {
                Add-Check $Num $Name 'BAD' "This Windows 11 version (build $build) is out of support. $grp support ended on $endTxt." $out 'High' 'Update to the latest Windows 11 version (25H2 or newer).'
            } else {
                $m = "Supported. $grp support for this version ends on $endTxt."
                if ($now.AddDays(90) -ge $end) { $m += ' It ends within 90 days, so plan the update.' }
                Add-Check $Num $Name 'GOOD' $m $out
            }
        } elseif ($build -gt 26200) {
            Add-Check $Num $Name 'GOOD' "Windows 11 build $build is newer than the builds this script knows, so it is treated as supported. (If it is a preview build, confirm by hand.)" $out
        } else {
            Add-Check $Num $Name 'NOT CHECKED' "Windows 11 build $build is not in the script list, so support could not be decided." $out
        }
    } elseif ($cap -match 'Server 201[69]|Server 202') {
        Add-Check $Num $Name 'GOOD' 'Supported Windows Server family.' $out
    } else {
        Add-Check $Num $Name 'NOT CHECKED' 'Could not decide support status from the Windows name.' $out
    }
}

Invoke-Check 2 'Windows Update history' {
    $dates = @()
    $hf = Get-HotFix | Where-Object { $_.InstalledOn }
    if ($hf) { $dates += ($hf | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn }
    try {
        $sess = New-Object -ComObject Microsoft.Update.Session
        $searcher = $sess.CreateUpdateSearcher()
        $cnt = $searcher.GetTotalHistoryCount()
        if ($cnt -gt 0) {
            $hist = $searcher.QueryHistory(0, [Math]::Min($cnt, 100)) |
                    Where-Object { $_.ResultCode -eq 2 -and $_.Title -notmatch 'Definition Update|Security Intelligence|Malicious Software Removal' } |
                    Sort-Object Date -Descending
            if ($hist) { $dates += ($hist | Select-Object -First 1).Date }
        }
    } catch { }
    $last = $dates | Sort-Object -Descending | Select-Object -First 1
    $reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
              (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
    $noAu = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
    $svcWu = Get-Service wuauserv
    $out = ''
    if ($last) {
        $days = [int]((Get-Date) - [datetime]$last).TotalDays
        $out += "Last update installed: $last  ($days days ago)`n"
    }
    $out += "Restart pending: $reboot`n"
    $out += "Automatic updates turned off by policy (NoAutoUpdate): $noAu`n"
    $out += "Windows Update service start type: $($svcWu.StartType)`n`nLatest installed updates:`n"
    $out += Fmt ($hf | Sort-Object InstalledOn -Descending | Select-Object HotFixID, Description, InstalledOn -First 10)
    if (-not $last) {
        Add-Check $Num $Name 'NOT CHECKED' 'No update history could be read.' $out
    } elseif ($days -gt 45) {
        Add-Check $Num $Name 'BAD' "Last update was $days days ago (more than 45 days)." $out 'High' 'Run Windows Update now and restart the PC. Keep automatic updates on.'
    } elseif ($noAu -eq 1 -or [string]$svcWu.StartType -eq 'Disabled') {
        Add-Check $Num $Name 'BAD' 'Automatic Windows Update is turned off.' $out 'High' 'Turn automatic updates back on.'
    } else {
        $m = "Last update was $days days ago."
        if ($reboot) { $m += ' A restart is pending.' }
        Add-Check $Num $Name 'GOOD' $m $out
    }
}

Invoke-Check 3 'Pending updates (needs internet)' {
    if (-not $CheckOnline) { Add-Check $Num $Name 'NOT CHECKED' 'Skipped (CheckOnline is off).' '(skipped)'; return }
    $job = Start-Job -ScriptBlock {
        $ErrorActionPreference = 'Stop'
        $s = New-Object -ComObject Microsoft.Update.Session
        $r = $s.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0')
        foreach ($u in $r.Updates) { [pscustomobject]@{ Title = [string]$u.Title; Severity = [string]$u.MsrcSeverity; Released = $u.LastDeploymentChangeTime } }
    }
    $done = Wait-Job $job -Timeout 150
    $res = $null
    if ($done -and $job.State -eq 'Completed') { $res = @(Receive-Job $job) } else { Stop-Job $job }
    Remove-Job $job -Force
    if ($null -eq $res) {
        Add-Check $Num $Name 'NOT CHECKED' 'Could not ask Microsoft for pending updates (no internet, timeout, or blocked).' '(no data)'
        return
    }
    $sec = @($res | Where-Object { $_.Title -notmatch 'Definition|Security Intelligence' })
    $secAll = @($sec | Where-Object { $_.Severity -match 'Critical|Important|Moderate|Low' -or ($_.Title -match 'Security Update|Cumulative Update' -and $_.Title -notmatch 'Preview') })
    $cut = (Get-Date).AddDays(-14)
    $secPending = @($secAll | Where-Object { ($null -eq $_.Released) -or ([datetime]$_.Released -lt $cut) })
    $recentCnt = $secAll.Count - $secPending.Count
    $pocU = (@($secPending | ForEach-Object { $d = ''; if ($null -ne $_.Released) { $d = '  (released ' + ([datetime]$_.Released).ToString('dd MMM yyyy') + ')' }; $_.Title + $d }) -join "`n")
    $important = @($secPending | Where-Object { $_.Severity -match 'Critical|Important' })
    $out = Fmt ($sec | Select-Object Title, Severity, Released) -Empty '(no pending updates)'
    if ($secPending.Count -gt 0) {
        $sv = 'Medium'; if ($important.Count -gt 0) { $sv = 'High' }
        Add-Check $Num $Name 'BAD' "$($secPending.Count) security update(s) have been waiting to install for more than 14 days." $out $sv 'Install the pending updates and restart the PC.' $pocU
    } else {
        $m = 'No security update has been waiting for more than 14 days.'
        if ($recentCnt -gt 0) { $m += " ($recentCnt newer update(s) are waiting, which is normal.)" }
        Add-Check $Num $Name 'GOOD' $m $out
    }
}

Invoke-Check 4 'Windows activation' {
    $lic = @(Get-CimInstance SoftwareLicensingProduct | Where-Object { $_.PartialProductKey -and $_.Name -match '^Windows' })
    $ok = @($lic | Where-Object { $_.LicenseStatus -eq 1 })
    $out = Fmt ($lic | Select-Object Name, LicenseStatus) + "`n(LicenseStatus 1 = licensed)"
    if ($lic.Count -eq 0) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read the Windows license.' $out }
    elseif ($ok.Count -gt 0) { Add-Check $Num $Name 'GOOD' 'Windows is activated (licensed).' $out }
    else { Add-Check $Num $Name 'BAD' 'Windows is not activated. This may mean an unlicensed or pirated copy.' $out 'Low' 'Activate Windows with a valid license.' }
}

Invoke-Check 5 'Outdated applications (needs internet)' {
    if (-not $CheckOnline) { Add-Check $Num $Name 'NOT CHECKED' 'Skipped (CheckOnline is off).' '(skipped)'; return }
    $wg = Get-Command winget.exe -ErrorAction SilentlyContinue
    $exe = $null
    if ($wg) { $exe = $wg.Source }
    elseif (Test-Path "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe") { $exe = "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe" }
    if (-not $exe) { Add-Check $Num $Name 'NOT CHECKED' 'winget is not available on this PC, so outdated apps could not be listed. Check app versions by hand.' '(winget not found)'; return }
    $job = Start-Job -ScriptBlock { param($e) & $e upgrade --accept-source-agreements --disable-interactivity 2>&1 | Out-String -Width 400 } -ArgumentList $exe
    $done = Wait-Job $job -Timeout 150
    $raw = $null
    if ($done -and $job.State -eq 'Completed') { $raw = [string](Receive-Job $job) } else { Stop-Job $job }
    Remove-Job $job -Force
    if (-not $raw) { Add-Check $Num $Name 'NOT CHECKED' 'winget did not answer (no internet or timeout).' '(no data)'; return }
    $raw = $raw -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
    $all = $raw -split "`r?`n"
    $idx = -1
    for ($i = 0; $i -lt $all.Count; $i++) { if ($all[$i] -match '^-{5,}') { $idx = $i; break } }
    $rowsU = @()
    if ($idx -ge 0) {
        for ($i = $idx + 1; $i -lt $all.Count; $i++) {
            $l = $all[$i].Trim()
            if ((-not $l) -or ($l -match 'upgrades available|require explicit|explicit targeting')) { break }
            $rowsU += $l
        }
    }
    if ($rowsU.Count -gt 0) {
        $hdr = ''; if ($idx -gt 0) { $hdr = $all[$idx - 1].Trim() }
        $out = "Apps with updates available:`n" + $hdr + "`n" + ($rowsU -join "`n")
        $h = ''; if ($idx -gt 0) { $h = [string]$all[$idx - 1] }
        $cI = $h.IndexOf('Id'); $cV = $h.IndexOf('Version'); $cA = $h.IndexOf('Available'); $cS = $h.IndexOf('Source')
        $pl = @()
        foreach ($rw in $rowsU) {
            if ($cI -gt 0 -and $cV -gt $cI -and $cA -gt $cV -and $rw.Length -gt $cA) {
                $nm = $rw.Substring(0, $cI).Trim()
                $vr = $rw.Substring($cV, $cA - $cV).Trim()
                $av = $rw.Substring($cA).Trim()
                if ($cS -gt $cA -and $rw.Length -gt $cS) { $av = $rw.Substring($cA, $cS - $cA).Trim() }
                $pl += ($nm + '   ' + $vr + '  ->  ' + $av)
            } else { $pl += $rw }
        }
        $pocW = "Installed version  ->  available version`n" + ($pl -join "`n")
        $key = @($rowsU | Where-Object { $_ -match 'Chrome|Edge|Firefox|Java|Adobe|Acrobat|7-Zip|WinRAR|VLC|Zoom|Teams|Office|Notepad\+\+|Python|OpenSSL|PuTTY|WinSCP|FileZilla' })
        if ($key.Count -gt 0) {
            Add-Check $Num $Name 'BAD' "$($rowsU.Count) app(s) are outdated, including important ones (browsers, Java, Adobe, Office, archive tools, etc.)." $out 'Medium' 'Update the listed applications.' $pocW
        } else {
            Add-Check $Num $Name 'BAD' "$($rowsU.Count) app(s) have updates available." $out 'Low' 'Update the listed applications.' $pocW
        }
    } elseif ($raw -match 'No installed package found|No applicable upgrade') {
        Add-Check $Num $Name 'GOOD' 'winget found no outdated apps.' $raw.Trim()
    } else {
        Add-Check $Num $Name 'NOT CHECKED' 'Could not read the winget result.' ($raw.Trim())
    }
}

# =============================================================================
# GROUP B - Malware Protection
# =============================================================================
$script:cat = 'Malware Protection'

Invoke-Check 6 'Antivirus' {
    $mp = $mpStatus
    $av = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct)
    $prods = @()
    foreach ($a in $av) {
        $st = [int64]$a.productState
        $prods += [pscustomobject]@{ Name = [string]$a.displayName; On = [bool]($st -band 0x1000); OutOfDate = [bool]($st -band 0x10) }
    }
    $third = @($prods | Where-Object { $_.Name -notmatch 'Defender' })
    $thirdOk = @($third | Where-Object { $_.On -and (-not $_.OutOfDate) })
    $defActive = ($mp -and ([string]$mp.AMRunningMode -notmatch 'Passive'))
    $lines = @()
    foreach ($p in $prods) {
        $rt = 'OFF'; if ($p.On) { $rt = 'ON' }
        $sg = 'up to date'; if ($p.OutOfDate) { $sg = 'OUT OF DATE' }
        $lines += ('Security Center: ' + $p.Name + ' | real-time protection ' + $rt + ' | signatures ' + $sg)
    }
    if ($mp) { $lines += "Defender: AntivirusEnabled=$($mp.AntivirusEnabled), RealTimeProtection=$($mp.RealTimeProtectionEnabled), SignatureAgeDays=$($mp.AntivirusSignatureAge), TamperProtected=$($mp.IsTamperProtected), Mode=$($mp.AMRunningMode)" }
    $out = '(no data)'
    if ($lines.Count -gt 0) { $out = $lines -join "`n" }
    if ($thirdOk.Count -gt 0) {
        Add-Check $Num $Name 'GOOD' ('Third-party antivirus is on and up to date: ' + (($thirdOk | ForEach-Object { $_.Name }) -join ', ')) $out
    } elseif ($defActive) {
        $issues = @()
        if (-not $mp.AntivirusEnabled) { $issues += 'Antivirus is turned off.' }
        if (-not $mp.RealTimeProtectionEnabled) { $issues += 'Real-time protection is off.' }
        if ($mp.AntivirusSignatureAge -gt 7) { $issues += "Virus signatures are $($mp.AntivirusSignatureAge) days old." }
        if ($issues.Count -gt 0) {
            Add-Check $Num $Name 'BAD' ($issues -join ' ') $out 'High' 'Turn on real-time protection and update the antivirus signatures.'
        } else {
            Add-Check $Num $Name 'GOOD' 'Defender is on, real-time protection is on, signatures are up to date.' $out
        }
    } elseif ($prods.Count -gt 0) {
        $okAny = @($prods | Where-Object { $_.On -and (-not $_.OutOfDate) })
        if ($okAny.Count -gt 0) {
            Add-Check $Num $Name 'GOOD' ('Windows Security Center reports real-time protection is on and signatures are up to date: ' + (($okAny | ForEach-Object { $_.Name }) -join ', ')) $out
        } else {
            $why = @($prods | ForEach-Object {
                $a1 = 'off'; if ($_.On) { $a1 = 'on' }
                $a2 = 'up to date'; if ($_.OutOfDate) { $a2 = 'out of date' }
                $_.Name + ' (' + $a1 + ', ' + $a2 + ')'
            })
            Add-Check $Num $Name 'BAD' ('No antivirus is both on and up to date: ' + ($why -join '; ') + '.') $out 'High' 'Turn on the antivirus and update it.'
        }
    } else {
        Add-Check $Num $Name 'NOT CHECKED' 'Could not read antivirus status.' $out
    }
}

Invoke-Check 7 'Defender hardening (exclusions, cloud, PUA, ASR)' {
    $pref = $mpPref
    $mp = $mpStatus
    if (-not $pref) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read Defender settings (a third-party antivirus may be in control).' '(no data)'; return }
    $exP  = @($pref.ExclusionPath | Where-Object { $_ })
    $exE  = @($pref.ExclusionExtension | Where-Object { $_ })
    $exPr = @($pref.ExclusionProcess | Where-Object { $_ })
    $asr  = @($pref.AttackSurfaceReductionRules_Ids | Where-Object { $_ })
    $out = "Cloud protection (MAPSReporting) = $($pref.MAPSReporting)   (0 = off)`nPUA protection = $($pref.PUAProtection)   (1 = on)`nNetwork protection = $($pref.EnableNetworkProtection)   (1 = on)`nASR rules configured = $($asr.Count)`nTamper protection = $($mp.IsTamperProtected)`nAntivirus mode = $($mp.AMRunningMode)`n`nExcluded paths: " + ($exP -join '; ') + "`nExcluded extensions: " + ($exE -join '; ') + "`nExcluded processes: " + ($exPr -join '; ')
    if ([string]$mp.AMRunningMode -match 'Passive') {
        Add-Check $Num $Name 'GOOD' 'Defender is in passive mode because another antivirus is in control.' $out
        return
    }
    $issues = @(); $sv = 'Low'
    $broadP = @($exP | Where-Object { $_.TrimEnd('\') -match '^[A-Za-z]:$|^[A-Za-z]:\\(Users|Windows|ProgramData|Temp)$' })
    $broadE = @($exE | Where-Object { $_ -match '^\.?(exe|dll|ps1|bat|cmd|vbs|js|scr)$' })
    if ($broadP.Count -gt 0) { $issues += ('Very wide exclusion path(s): ' + ($broadP -join ', ') + '.'); $sv = 'Medium' }
    if ($broadE.Count -gt 0) { $issues += ('Risky excluded file type(s): ' + ($broadE -join ', ') + '.'); $sv = 'Medium' }
    if ($pref.MAPSReporting -eq 0) { $issues += 'Cloud-delivered protection is off.' }
    if ($pref.PUAProtection -ne 1) { $issues += 'PUA (unwanted app) protection is off.' }
    if ($pref.EnableNetworkProtection -ne 1) { $issues += 'Network protection is not enforced.' }
    if ($asr.Count -eq 0) { $issues += 'No Attack Surface Reduction rules are set.' }
    if ($mp -and (-not $mp.IsTamperProtected)) { $issues += 'Tamper protection is off.' }
    if ($issues.Count -gt 0) { Add-Check $Num $Name 'BAD' ($issues -join ' ') $out $sv 'In Windows Security (or Defender policy): remove wide exclusions, turn on cloud protection, PUA, network protection, tamper protection and ASR rules.' }
    else { Add-Check $Num $Name 'GOOD' 'Cloud, PUA, network protection, ASR and tamper protection are on, and no risky exclusions.' $out }
}

Invoke-Check 8 'EDR agent' {
    $nameRx = '^(Sense|CSFalconService|SentinelAgent|CbDefense|CylanceSvc|CortexXDR|cyserver|ElasticEndpoint|elastic-agent|WazuhSvc|SophosED.*)$'
    $dispRx = 'CrowdStrike|SentinelOne|Carbon Black|Cylance|Cortex XDR|Cybereason|Elastic Endpoint|Wazuh|Defender for Endpoint|Intercept X'
    $svc = @(Get-Service | Where-Object { $_.Name -match $nameRx -or $_.DisplayName -match $dispRx })
    $running = @($svc | Where-Object { [string]$_.Status -eq 'Running' })
    $onb = RegVal 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' 'OnboardingState'
    $out = "Defender for Endpoint onboarding state = $onb   (1 = onboarded)`n`nEDR-type services found:`n" + (Fmt ($svc | Select-Object Name, DisplayName, Status) -Empty '(none)')
    if ($running.Count -gt 0 -or $onb -eq 1) { Add-Check $Num $Name 'GOOD' 'An EDR agent is running or the PC is onboarded to Defender for Endpoint.' $out }
    else { Add-Check $Num $Name 'BAD' 'No running EDR agent found (normal antivirus is not EDR).' $out 'Low' 'Install and onboard an EDR agent if the client policy requires it.' }
}

# =============================================================================
# GROUP C - Data Protection
# =============================================================================
$script:cat = 'Data Protection'

Invoke-Check 9 'BitLocker (disk encryption)' {
    $vols = Get-BitLockerVolume
    if ($vols) {
        $osv = $vols | Where-Object { [string]$_.VolumeType -eq 'OperatingSystem' }
        if (-not $osv) { $osv = $vols | Where-Object { $_.MountPoint -eq $env:SystemDrive } }
        $out = Fmt ($vols | Select-Object MountPoint, VolumeType, ProtectionStatus, EncryptionPercentage, EncryptionMethod, VolumeStatus)
        $okOs = $osv | Where-Object { [string]$_.ProtectionStatus -eq 'On' -and $_.EncryptionPercentage -eq 100 }
        $pocB = Fmt ($vols | Select-Object MountPoint, VolumeType, ProtectionStatus, EncryptionPercentage, VolumeStatus)
        if (-not $osv) {
            Add-Check $Num $Name 'NOT CHECKED' 'Could not find the Windows drive in the BitLocker list.' $out
        } elseif ($okOs) {
            $fixed = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { [string]$_.DeviceID })
            $dataBad = @($vols | Where-Object { ([string]$_.VolumeType -ne 'OperatingSystem') -and ($fixed -contains [string]$_.MountPoint) -and ([string]$_.ProtectionStatus -ne 'On') })
            if ($dataBad.Count -gt 0) {
                Add-Check $Num $Name 'BAD' ('The Windows drive is encrypted, but these data drive(s) are not: ' + (($dataBad | ForEach-Object { $_.MountPoint }) -join ', ') + '. If the disk is stolen, the data can be read.') $out 'Medium' 'Turn on BitLocker for the data drives too and save the recovery keys safely.' (Fmt ($dataBad | Select-Object MountPoint, VolumeType, ProtectionStatus, EncryptionPercentage, VolumeStatus))
            } else {
                Add-Check $Num $Name 'GOOD' 'The Windows drive and all fixed data drives are encrypted and protection is on.' $out
            }
        } else {
            Add-Check $Num $Name 'BAD' 'The Windows drive is not fully encrypted or protection is off. (Third-party disk encryption, if any, cannot be detected by this script.)' $out 'High' 'Turn on BitLocker for the Windows drive and save the recovery key safely.' $pocB
        }
    } else {
        $mb = (manage-bde -status 2>&1 | Out-String).Trim()
        if ($mb -match 'Protection On') {
            Add-Check $Num $Name 'GOOD' 'BitLocker protection is on.' $mb
        } elseif ($mb -match 'Protection Off') {
            Add-Check $Num $Name 'BAD' 'BitLocker protection is off. (Third-party disk encryption, if any, cannot be detected by this script.)' $mb 'High' 'Turn on BitLocker for the Windows drive and save the recovery key safely.'
        } else {
            Add-Check $Num $Name 'NOT CHECKED' 'Could not read BitLocker status (it may not be available on this Windows edition).' $mb
        }
    }
}

Invoke-Check 10 'Secure Boot and TPM' {
    $sbOn = $null
    try { $sbOn = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $sbOn = $null }
    $tpm = Get-Tpm
    $out = "Secure Boot enabled: $sbOn   (empty = not supported or the PC uses legacy BIOS)`nTPM present: $($tpm.TpmPresent)`nTPM ready: $($tpm.TpmReady)"
    $bad = @()
    if ($sbOn -ne $true) { $bad += 'Secure Boot is off or not supported.' }
    if (-not $tpm) { $bad += 'TPM status could not be read.' }
    elseif (-not $tpm.TpmPresent) { $bad += 'No TPM found.' }
    if ($bad.Count -gt 0) { Add-Check $Num $Name 'BAD' ($bad -join ' ') $out 'Low' 'Turn on Secure Boot (UEFI) and TPM in the BIOS settings if the hardware supports them.' }
    else { Add-Check $Num $Name 'GOOD' 'Secure Boot is on and a TPM is present.' $out }
}

Invoke-Check 11 'USB storage' {
    $v = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' 'Start'
    $out = "USBSTOR Start = $v   (3 = USB storage allowed, 4 = blocked)"
    if ($null -eq $v) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read the USB setting.' $out }
    elseif ($v -eq 4) { Add-Check $Num $Name 'GOOD' 'USB storage is blocked.' $out }
    elseif (-not $RequireUsbBlocked) { Add-Check $Num $Name 'GOOD' 'USB storage is allowed, and the client allows it.' $out }
    else { Add-Check $Num $Name 'BAD' 'USB storage is allowed.' $out 'Low' 'Block USB storage by policy if the client does not need it.' }
}

Invoke-Check 12 'Backup (restore points)' {
    $out = (vssadmin list shadows 2>&1 | Out-String).Trim()
    if ($out -match 'Shadow Copy ID') { Add-Check $Num $Name 'GOOD' 'Restore points exist. These are local only and are not a full backup. Confirm cloud or server backup with the client.' $out }
    elseif ($out -match 'No items found|no shadow copies') { Add-Check $Num $Name 'BAD' 'No local restore points found. (This script cannot see cloud or server backups.)' $out 'Low' 'Make sure a regular backup (cloud, server or external drive) exists.' }
    else { Add-Check $Num $Name 'NOT CHECKED' 'Could not read restore points (vssadmin did not answer in the normal way).' $out }
}

# =============================================================================
# GROUP D - Accounts and Access
# =============================================================================
$script:cat = 'Accounts and Access'

Invoke-Check 13 'Local user accounts' {
    $users = @($localUsers)
    $bad = @()
    $sev = 1    # 1 = Low, 2 = Medium, 3 = High
    $g = @($users | Where-Object { $_.Enabled -and $_.SID.Value -like '*-501' })
    if ($g.Count -gt 0) { $bad += 'Guest account is enabled.'; $sev = [math]::Max($sev, 2) }
    $adm = @($users | Where-Object { $_.Enabled -and $_.SID.Value -like '*-500' })
    if ($adm.Count -gt 0) { $bad += 'Built-in Administrator account is enabled.'; $sev = [math]::Max($sev, 2) }
    $np = @($users | Where-Object { $_.Enabled -and (-not $_.PasswordRequired) -and ($_.SID.Value -notlike '*-501') -and ([string]$_.PrincipalSource -ne 'MicrosoftAccount') })
    $npNever = @($np | Where-Object { -not $_.PasswordLastSet })
    $npSet = @($np | Where-Object { $_.PasswordLastSet })
    if ($npNever.Count -gt 0) { $bad += ('Enabled account(s) with NO password set: ' + (($npNever | ForEach-Object { $_.Name }) -join ', ') + '.'); $sev = 3 }
    if ($npSet.Count -gt 0) { $bad += ('Enabled account(s) where Windows does not require a password, so a blank password is allowed (a password was set earlier, so one may exist; this script cannot prove it is blank): ' + (($npSet | ForEach-Object { $_.Name }) -join ', ') + '.') }
    $stale = @($users | Where-Object { $_.Enabled -and $_.LastLogon -and $_.LastLogon -lt (Get-Date).AddDays(-90) })
    if ($stale.Count -gt 0) { $bad += ('Enabled account(s) not used for 90+ days: ' + (($stale | ForEach-Object { $_.Name }) -join ', ') + '.') }
    $out = Fmt ($users | Select-Object Name, Enabled, PasswordRequired, PasswordLastSet, LastLogon)
    $sevText = @('Low', 'Low', 'Medium', 'High')[$sev]
    $pocA = Fmt ($users | Where-Object { $_.Enabled } | Select-Object Name, Enabled, PasswordRequired, PasswordLastSet)
    if ($users.Count -eq 0) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read local users.' $out }
    elseif ($bad.Count -gt 0) { Add-Check $Num $Name 'BAD' ($bad -join ' ') $out $sevText 'Disable Guest and the built-in Administrator, disable unused accounts, and set a strong password on every account.' $pocA }
    else { Add-Check $Num $Name 'GOOD' 'Guest and built-in Administrator are off, all enabled accounts need a password, none unused for 90+ days.' $out }
}

Invoke-Check 14 'Administrators group' {
    $grp = (Get-LocalGroup | Where-Object { $_.SID.Value -eq 'S-1-5-32-544' }).Name
    if (-not $grp) { $grp = 'Administrators' }
    $bn = ($localUsers | Where-Object { $_.SID.Value -like '*-500' }).Name
    try {
        $members = Get-LocalGroupMember -Group $grp -ErrorAction Stop
        $out = Fmt ($members | Select-Object Name, ObjectClass, PrincipalSource)
        $extra = @($members | Where-Object { $_.Name -notlike "*\$bn" -and $_.Name -notlike '*\Domain Admins' -and ($ApprovedAdmins -notcontains $_.Name) })
        if ($extra.Count -gt 1) {
            Add-Check $Num $Name 'BAD' ("$($extra.Count) admin users besides the built-in Administrator: " + (($extra | ForEach-Object { $_.Name }) -join ', ') + '.') $out 'Medium' 'Keep only the people who really need admin rights. Move others to normal user accounts.'
        } else {
            Add-Check $Num $Name 'GOOD' 'At most 1 admin user besides the built-in Administrator (and Domain Admins).' $out
        }
    } catch {
        $raw = (net localgroup $grp 2>&1 | Out-String).Trim()
        Add-Check $Num $Name 'NOT CHECKED' 'Could not read the Administrators list in detail. Raw list is below.' $raw
    }
}

Invoke-Check 15 'Password policy' {
    $minLen = Get-SecVal 'MinimumPasswordLength'
    $lock   = Get-SecVal 'LockoutBadCount'
    $cplx   = Get-SecVal 'PasswordComplexity'
    $maxAge = Get-SecVal 'MaximumPasswordAge'
    $out = "Minimum password length : $minLen`nLockout after bad attempts : $lock   (0 = never locks)`nPassword complexity : $cplx   (1 = on)`nMaximum password age (days) : $maxAge   (-1 = never expires)`n`nPolicy as seen on this PC ($domainText)."
    if ($null -eq $minLen -or $null -eq $lock -or $null -eq $cplx) {
        Add-Check $Num $Name 'NOT CHECKED' 'Could not read the password policy.' $out
    } else {
        $bad = @()
        if ([int]$minLen -lt 8) { $bad += "Minimum password length is $minLen (should be 8 or more)." }
        if ([int]$lock -eq 0) { $bad += 'Account never locks after wrong passwords.' }
        if (([int]$cplx -eq 0) -and ([int]$minLen -lt 14)) { $bad += 'Password complexity is off (and the minimum length is below 14).' }
        if ($bad.Count -gt 0) { Add-Check $Num $Name 'BAD' ($bad -join ' ') $out 'Medium' 'Set minimum length 8+ (12+ is better), turn on complexity, and lock accounts after 5-10 wrong tries.' }
        else { Add-Check $Num $Name 'GOOD' 'Length is 8 or more, complexity is on, and accounts lock after wrong passwords.' $out }
    }
}

Invoke-Check 16 'UAC and auto-login' {
    $uac = RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
    $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $auto = [string]$wl.AutoAdminLogon
    $hasPw = [bool]($wl.PSObject.Properties.Name -contains 'DefaultPassword')
    $out = "UAC (EnableLUA) = $uac   (1 = on)`nAuto-login (AutoAdminLogon) = $auto   (1 = on)`nPassword stored for auto-login: $hasPw"
    $bad = @()
    if ($uac -ne 1) { $bad += 'UAC is off.' }
    if ($auto -eq '1') { $bad += 'Windows signs in automatically at startup (auto-login is on).' }
    if ($hasPw) { $bad += 'A password is stored in plain text for auto-login.' }
    if ($null -eq $uac) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read the UAC setting.' $out }
    elseif ($bad.Count -gt 0) { Add-Check $Num $Name 'BAD' ($bad -join ' ') $out 'High' 'Turn on UAC and remove auto-login.' }
    else { Add-Check $Num $Name 'GOOD' 'UAC is on and auto-login is not used.' $out }
}

Invoke-Check 17 'Screen lock (inactivity)' {
    $inact = RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs'
    $ssAct = RegVal 'HKCU:\Control Panel\Desktop' 'ScreenSaveActive'
    $ssSec = RegVal 'HKCU:\Control Panel\Desktop' 'ScreenSaverIsSecure'
    $ssTim = RegVal 'HKCU:\Control Panel\Desktop' 'ScreenSaveTimeOut'
    $out = "Machine inactivity limit (policy) = $inact seconds`nScreen saver active = $ssAct, password on resume = $ssSec, timeout = $ssTim seconds`n(Screen saver values are for the user running this script.)"
    $okPolicy = ($null -ne $inact) -and ([int]$inact -gt 0) -and ([int]$inact -le 900)
    $okSaver = ($ssAct -eq '1') -and ($ssSec -eq '1') -and ($null -ne $ssTim) -and ([int]$ssTim -le 900)
    if ($okPolicy -or $okSaver) { Add-Check $Num $Name 'GOOD' 'The PC locks itself after 15 minutes or less of inactivity.' $out }
    else { Add-Check $Num $Name 'BAD' 'No auto-lock (15 minutes or less) was found in policy or screen saver. (A lock set only in Power settings is not read by this script.)' $out 'Low' 'Set an inactivity lock of 15 minutes or less by policy.' }
}

Invoke-Check 18 'Credential protection' {
    $wd  = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    $lm  = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
    $ppl = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
    $dg  = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard
    $cg  = @($dg.SecurityServicesRunning) -contains 1
    $out = "WDigest UseLogonCredential = $wd   (1 = passwords kept in memory, bad)`nNTLM level (LmCompatibilityLevel) = $lm   (3 or more is good)`nLSA protection (RunAsPPL) = $ppl   (1 or 2 = on)`nCredential Guard running = $cg"
    $bad = @(); $sv = 'Low'
    if ($wd -eq 1) { $bad += 'WDigest is on (plain-text passwords can be stolen from memory).'; $sv = 'High' }
    if ($null -ne $lm -and [int]$lm -lt 3) { $bad += "Old NTLM/LM authentication is allowed (level $lm)."; $sv = 'High' }
    if (-not ($ppl -eq 1 -or $ppl -eq 2 -or $cg)) { $bad += 'LSA protection and Credential Guard are not enabled (on some new Windows 11 installs LSA protection is on by default; check Windows Security > Device security > Core isolation).' }
    if ($bad.Count -gt 0) { Add-Check $Num $Name 'BAD' ($bad -join ' ') $out $sv 'Turn off WDigest, set NTLM level to 3 or higher, and turn on LSA protection / Credential Guard.' }
    else { Add-Check $Num $Name 'GOOD' 'WDigest is off, NTLM level is safe, and LSA protection or Credential Guard is on.' $out }
}

Invoke-Check 19 'Local admin password management (LAPS)' {
    if (-not $cs.PartOfDomain) {
        Add-Check $Num $Name 'GOOD' 'This PC is not domain joined. (LAPS is for domain PCs; make sure the local admin password is unique and strong.)' '(workgroup PC)'
        return
    }
    $a = Test-Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS'
    $b = Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'
    $c = Test-Path "$env:ProgramFiles\LAPS\CSE\AdmPwd.dll"
    $out = "Windows LAPS policy found: $a`nLegacy LAPS policy found: $b`nLegacy LAPS client found: $c"
    if ($a -or $b -or $c) { Add-Check $Num $Name 'GOOD' 'LAPS is set up.' $out }
    else { Add-Check $Num $Name 'BAD' 'LAPS was not found on this domain PC.' $out 'Medium' 'Deploy Windows LAPS so every PC has a unique local admin password.' }
}

# =============================================================================
# GROUP E - Network and Services
# =============================================================================
$script:cat = 'Network and Services'

Invoke-Check 20 'Windows Firewall' {
    $fw = @(Get-NetFirewallProfile)
    $off = @($fw | Where-Object { [string]$_.Enabled -ne 'True' })
    $out = Fmt ($fw | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
    $fwp = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName FirewallProduct)
    $thirdFw = @($fwp | Where-Object { ([string]$_.displayName -notmatch 'Windows') -and ([int64]$_.productState -band 0x1000) })
    $out += "`n`nFirewall products registered in Windows Security Center: " + (($fwp | ForEach-Object { [string]$_.displayName }) -join ', ')
    if ($fw.Count -eq 0) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read firewall profiles.' $out }
    elseif ($off.Count -gt 0 -and $thirdFw.Count -gt 0) { Add-Check $Num $Name 'GOOD' ('Windows Firewall is off for some profiles, but a third-party firewall is on: ' + (($thirdFw | ForEach-Object { [string]$_.displayName }) -join ', ') + '.') $out }
    elseif ($off.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Windows Firewall is OFF for: ' + (($off | ForEach-Object { $_.Name }) -join ', ') + ', and no active third-party firewall was found.') $out 'High' 'Turn on Windows Firewall for all profiles.' }
    else { Add-Check $Num $Name 'GOOD' 'Firewall is ON for Domain, Private and Public.' $out }
}

Invoke-Check 21 'Firewall inbound allow rules' {
    $rules = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow)
    $pf = @{};  foreach ($x in (Get-NetFirewallPortFilter -All))        { $pf[[string]$x.InstanceID] = $x }
    $af = @{};  foreach ($x in (Get-NetFirewallAddressFilter -All))     { $af[[string]$x.InstanceID] = $x }
    $apf = @{}; foreach ($x in (Get-NetFirewallApplicationFilter -All)) { $apf[[string]$x.InstanceID] = $x }
    $svf = @{}; foreach ($x in (Get-NetFirewallServiceFilter -All))     { $svf[[string]$x.InstanceID] = $x }
    $matched = @($rules | Where-Object { $pf.ContainsKey([string]$_.Name) }).Count
    if ($rules.Count -eq 0 -or $matched -eq 0) {
        Add-Check $Num $Name 'NOT CHECKED' 'Could not read inbound firewall rules in detail.' "Inbound allow rules found: $($rules.Count)"
        return
    }
    $risky = '21', '22', '23', '135', '139', '445', '3389', '5900', '5985', '5986'
    $flag = @()
    foreach ($r in $rules) {
        $id = [string]$r.Name
        $p = $pf[$id]; $a = $af[$id]; $ap = $apf[$id]; $sf = $svf[$id]
        $ports  = @($p.LocalPort | ForEach-Object { [string]$_ })
        $remote = @($a.RemoteAddress | ForEach-Object { [string]$_ })
        $prof = [string]$r.Profile
        $prog = [string]$ap.Program
        $pk = [string]$ap.Package
        $sv1 = [string]$sf.Service
        # A rule tied to one app package, one service or one user is not "open to everything"
        $scoped = (($pk) -and ($pk -ne 'Any')) -or (($sv1) -and ($sv1 -ne 'Any')) -or ([string]$r.Owner) -or ([string]$r.PackageFamilyName)
        $anyRemote = ($remote -contains 'Any')
        $pubOrAny = ($prof -match 'Public|Any')
        $riskyPort = (@($ports | Where-Object { $risky -contains $_ }).Count -gt 0)
        $allowAll = ($anyRemote -and (-not $scoped) -and ($ports -contains 'Any') -and (($prog -eq 'Any') -or ($prog -eq '')) -and ([string]$p.Protocol -eq 'Any'))
        if ($allowAll -or ($anyRemote -and $pubOrAny -and $riskyPort)) {
            $dn = [string]$r.DisplayName
            if ((-not $dn) -or $dn.StartsWith('@')) { $dn = $id }
            $flag += [pscustomobject]@{ Rule = $dn; Profile = $prof; Protocol = [string]$p.Protocol; LocalPort = ($ports -join ','); Remote = ($remote -join ','); Program = $prog }
        }
    }
    $out = "Enabled inbound allow rules: $($rules.Count)`nRisky rules found: $($flag.Count)`n`n" + (Fmt $flag -Empty '(none)')
    $pocF = (@($flag | ForEach-Object { $_.Rule + '  |  profile: ' + $_.Profile + '  |  protocol: ' + $_.Protocol + '  |  port: ' + $_.LocalPort + '  |  from: ' + $_.Remote + '  |  program: ' + $_.Program }) -join "`n")
    if ($flag.Count -gt 0) { Add-Check $Num $Name 'BAD' "$($flag.Count) inbound allow rule(s) are too open (allow everything, or open a risky port to any address on the Public profile)." $out 'High' 'Delete or narrow these rules. Allow only the needed ports and only from trusted IP addresses.' $pocF }
    else { Add-Check $Num $Name 'GOOD' 'No inbound allow rule opens risky ports to any address, and none allows all traffic.' $out }
}

Invoke-Check 22 'Open (listening) ports' {
    $p = Get-NetTCPConnection -State Listen |
         Select-Object LocalAddress, LocalPort, @{ n = 'Process'; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } } |
         Sort-Object LocalPort, LocalAddress
    $risky = 21, 23, 5800, 5900, 5901
    $hit = $p | Where-Object { ($risky -contains $_.LocalPort) -and ($_.LocalAddress -notin '127.0.0.1', '::1') } | ForEach-Object { $_.LocalPort } | Sort-Object -Unique
    $hitRows = @($p | Where-Object { ($risky -contains $_.LocalPort) -and ($_.LocalAddress -notin '127.0.0.1', '::1') })
    $pocP = (@($hitRows | ForEach-Object { 'Port ' + $_.LocalPort + ' is listening on ' + $_.LocalAddress + ' (process: ' + $_.Process + ')' }) -join "`n")
    if (-not $p) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read listening ports.' (Fmt $p) }
    elseif ($hit) { Add-Check $Num $Name 'BAD' ('Risky port(s) open: ' + ($hit -join ', ') + ' (21 FTP, 23 Telnet, 5800/5900/5901 VNC).') (Fmt $p) 'High' 'Stop the service that uses these ports, or block the ports in the firewall.' $pocP }
    else { Add-Check $Num $Name 'GOOD' 'No risky ports (FTP, Telnet, VNC) are open. Full port list is below for reference.' (Fmt $p) }
}

Invoke-Check 23 'Shared folders' {
    $s = Get-SmbShare
    $extra = @($s | Where-Object { (($_.Name -notin 'ADMIN$', 'IPC$', 'print$')) -and ($_.Name -notmatch '^[A-Za-z]\$$') -and ($ApprovedShares -notcontains $_.Name) })
    $out = Fmt ($s | Select-Object Name, Path, Description)
    if (-not $s) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read shares.' $out }
    elseif ($extra.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Extra share(s) found: ' + (($extra | ForEach-Object { $_.Name }) -join ', ') + '.') $out 'Medium' 'Remove shares that are not needed.' }
    else { Add-Check $Num $Name 'GOOD' 'Only default Windows shares found.' $out }
}

Invoke-Check 24 'Share permissions' {
    $userShares = @(Get-SmbShare | Where-Object { (($_.Name -notin 'ADMIN$', 'IPC$', 'print$')) -and ($_.Name -notmatch '^[A-Za-z]\$$') })
    if ($userShares.Count -eq 0) { Add-Check $Num $Name 'GOOD' 'There are no user shares, so there are no share permissions to check.' '(no user shares)'; return }
    $issues = @(); $rows = @(); $ntfsLines = @()
    $sev = 1    # 1 = Low, 2 = Medium, 3 = High
    foreach ($sh in $userShares) {
        $shareBroad = @()
        foreach ($a in @(Get-SmbShareAccess -Name $sh.Name)) {
            $rows += [pscustomobject]@{ Share = $sh.Name; Account = [string]$a.AccountName; Right = [string]$a.AccessRight; Type = [string]$a.AccessControlType }
            if (([string]$a.AccountName -match 'Everyone|Anonymous|Authenticated Users|Guests') -and ([string]$a.AccessControlType -eq 'Allow')) { $shareBroad += $a }
        }
        $shareWrite = @($shareBroad | Where-Object { [string]$_.AccessRight -match 'Full|Change' })
        $ntfsWrite = @()
        $isRoot = $false
        if ($sh.Path) {
            $isRoot = ([string]$sh.Path -match '^[A-Za-z]:\\?$')
            $acl = Get-Acl -Path $sh.Path
            foreach ($ace in @($acl.Access)) {
                if (([string]$ace.IdentityReference -match '^Everyone$|Authenticated Users|^BUILTIN\\Users$') -and ([string]$ace.AccessControlType -eq 'Allow') -and ([string]$ace.FileSystemRights -match 'FullControl|Modify|Write')) {
                    $ntfsWrite += $ace
                    $ntfsLines += ('NTFS on ' + $sh.Path + ' : ' + [string]$ace.IdentityReference + ' has ' + [string]$ace.FileSystemRights)
                }
            }
        }
        if ($shareWrite.Count -gt 0 -and $ntfsWrite.Count -gt 0) {
            $issues += ("Share '" + $sh.Name + "' (" + $sh.Path + '): ' + [string]$shareWrite[0].AccountName + ' has ' + [string]$shareWrite[0].AccessRight + ' on the share, and ' + [string]$ntfsWrite[0].IdentityReference + ' can change files on disk. Anyone on the network can change or delete the files.')
            $sev = 3
        } elseif ($shareWrite.Count -gt 0) {
            $issues += ("Share '" + $sh.Name + "': " + [string]$shareWrite[0].AccountName + ' has ' + [string]$shareWrite[0].AccessRight + ' on the share (the folder permissions on disk still limit this).')
        } elseif ($shareBroad.Count -gt 0 -and $isRoot) {
            $issues += ("Whole drive '" + $sh.Path + "' is shared and " + [string]$shareBroad[0].AccountName + ' can read it.')
            $sev = [math]::Max($sev, 2)
        }
    }
    $out = Fmt $rows
    if ($ntfsLines.Count -gt 0) { $out += "`n`n" + ($ntfsLines -join "`n") }
    $sevText = @('Low', 'Low', 'Medium', 'High')[$sev]
    if ($issues.Count -gt 0) { Add-Check $Num $Name 'BAD' ($issues -join ' ') $out $sevText 'Remove Everyone/Anonymous access. Share only the folders that are needed, and give access to named users or groups only.' }
    else { Add-Check $Num $Name 'GOOD' 'No user share gives Everyone or Anonymous change/full access.' $out }
}

Invoke-Check 25 'Remote Desktop (RDP)' {
    $ts  = RegVal 'HKLM:\System\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    $nla = RegVal 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    $out = "fDenyTSConnections = $ts   (1 = RDP off, 0 = RDP on)`nUserAuthentication (NLA) = $nla   (1 = NLA required)"
    if ($ts -eq 1) { Add-Check $Num $Name 'GOOD' 'RDP is off.' $out }
    elseif ($ts -eq 0 -and $nla -eq 1) { Add-Check $Num $Name 'BAD' 'RDP is ON (NLA is required).' $out 'Medium' 'Turn RDP off unless it is needed. If needed, allow only approved users and approved IP addresses.' }
    elseif ($ts -eq 0) { Add-Check $Num $Name 'BAD' 'RDP is ON and NLA is not required.' $out 'High' 'Turn RDP off, or at least require NLA and limit who can connect.' }
    else { Add-Check $Num $Name 'NOT CHECKED' 'Could not read the RDP setting.' $out }
}

Invoke-Check 26 'SMB settings' {
    $s = Get-SmbServerConfiguration
    $c = Get-SmbClientConfiguration
    $bad = @()
    $sev = 'Medium'
    if ($s.EnableSMB1Protocol) { $bad += 'SMB1 (old, unsafe) is enabled.'; $sev = 'High' }
    if (-not $s.RequireSecuritySignature) { $bad += 'SMB signing is not required on the server side.' }
    if ($c -and (-not $c.RequireSecuritySignature)) { $bad += 'SMB signing is not required on the client side.' }
    $out = "SERVER`n" + (Fmt ($s | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EnableSecuritySignature) -List) +
           "`n`nCLIENT`n" + (Fmt ($c | Select-Object RequireSecuritySignature, EnableSecuritySignature) -List)
    if (-not $s) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read SMB settings.' $out }
    elseif ($bad.Count -gt 0) { Add-Check $Num $Name 'BAD' ($bad -join ' ') $out $sev 'Turn off SMB1. Require SMB signing after testing that it works with the client network.' }
    else { Add-Check $Num $Name 'GOOD' 'SMB1 is off and SMB signing is required.' $out }
}

Invoke-Check 27 'LLMNR and NetBIOS' {
    $llmnr = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    $nics = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Where-Object { $_.Description -notmatch 'Virtual|Hyper-V|VMware|VirtualBox|Loopback|Bluetooth|TAP-|Npcap|WAN Miniport|Wi-Fi Direct|Pseudo' })
    $nbBad = @($nics | Where-Object { $_.TcpipNetbiosOptions -ne 2 })
    $llTxt = 'not set (LLMNR is ON by default)'
    if ($null -ne $llmnr) { $llTxt = [string]$llmnr + '   (0 = disabled)' }
    $out = "LLMNR policy (EnableMulticast) = $llTxt`n`nNetBIOS over TCP/IP per network adapter (2 = disabled, 0 or 1 = on):`n" + (Fmt ($nics | Select-Object Description, TcpipNetbiosOptions))
    $pocL = "LLMNR policy (EnableMulticast) = $llTxt"
    if ($nbBad.Count -gt 0) { $pocL += "`nNetBIOS over TCP/IP is not disabled on:`n" + (Fmt ($nbBad | Select-Object Description, TcpipNetbiosOptions)) }
    $bad = @()
    if ($llmnr -ne 0) { $bad += 'LLMNR is not disabled.' }
    if ($nbBad.Count -gt 0) { $bad += 'NetBIOS over TCP/IP is on for at least one network adapter.' }
    if ($bad.Count -gt 0) { Add-Check $Num $Name 'BAD' ($bad -join ' ') $out 'Medium' 'Disable LLMNR by policy and turn off NetBIOS over TCP/IP (they help attackers steal password hashes on the local network).' $pocL }
    else { Add-Check $Num $Name 'GOOD' 'LLMNR and NetBIOS over TCP/IP are disabled.' $out }
}

Invoke-Check 28 'WinRM and Remote Registry' {
    $winrm = Get-Service WinRM
    $rr = Get-Service RemoteRegistry
    $out = "WinRM service: $($winrm.Status) ($($winrm.StartType))`nRemote Registry service: $($rr.Status) ($($rr.StartType))"
    $bad = @()
    if ([string]$winrm.Status -eq 'Running') { $bad += 'WinRM (remote PowerShell) is running.' }
    if ([string]$rr.Status -eq 'Running') { $bad += 'Remote Registry service is running.' }
    if ($bad.Count -gt 0) { Add-Check $Num $Name 'BAD' ($bad -join ' ') $out 'Medium' 'Stop and disable these services if the client does not use them for management.' }
    else { Add-Check $Num $Name 'GOOD' 'WinRM and Remote Registry are not running.' $out }
}

Invoke-Check 29 'Old SSL/TLS protocols' {
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $rows = @(); $bad = @()
    foreach ($proto in 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1') {
        foreach ($side in 'Client', 'Server') {
            $k = "$base\$proto\$side"
            $en = RegVal $k 'Enabled'
            $dbd = RegVal $k 'DisabledByDefault'
            if ($null -ne $en -or $null -ne $dbd) {
                $rows += [pscustomobject]@{ Protocol = $proto; Side = $side; Enabled = $en; DisabledByDefault = $dbd }
                if ($en -eq 1 -and $dbd -ne 1) { $bad += "$proto ($side)" }
            }
        }
    }
    $out = Fmt $rows -Empty '(no explicit settings found, so Windows defaults apply)'
    if ($bad.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Old protocol(s) are explicitly turned on: ' + ($bad -join ', ') + '.') $out 'Medium' 'Disable SSL 2.0/3.0 and TLS 1.0/1.1. Use TLS 1.2 or higher.' }
    else { Add-Check $Num $Name 'GOOD' 'No old SSL/TLS protocol is explicitly turned on.' $out }
}

# =============================================================================
# GROUP F - Remote Access
# =============================================================================
$script:cat = 'Remote Access'

Invoke-Check 30 'Remote access tools' {
    $pat = 'anydesk|teamviewer|vnc|rustdesk|ultraviewer|screenconnect|connectwise|splashtop|logmein|ammyy|supremo|radmin'
    $svc = Get-Service | Where-Object { $_.Name -match $pat -or $_.DisplayName -match $pat }
    $app = $sw | Where-Object { $_.DisplayName -match $pat }
    $names = @()
    $names += $svc | ForEach-Object { $_.DisplayName }
    $names += $app | ForEach-Object { $_.DisplayName }
    $names = @($names | Where-Object { $_ } | Sort-Object -Unique)
    $unapproved = @()
    foreach ($nm in $names) {
        $ok = $false
        foreach ($a in $ApprovedRemoteTools) { if ($nm -like "*$a*") { $ok = $true } }
        if (-not $ok) { $unapproved += $nm }
    }
    $out = "Services found:`n" + (Fmt ($svc | Select-Object Name, DisplayName, Status) -Empty '(none)') +
           "`n`nInstalled programs found:`n" + (Fmt ($app | Select-Object DisplayName, DisplayVersion) -Empty '(none)')
    $pocR = @()
    foreach ($x in @($svc)) { if ($unapproved -contains [string]$x.DisplayName) { $pocR += ('Service: ' + $x.DisplayName + '   status: ' + $x.Status) } }
    foreach ($x in @($app)) { if ($unapproved -contains [string]$x.DisplayName) { $pocR += ('Installed program: ' + $x.DisplayName + '   version: ' + $x.DisplayVersion) } }
    if ($unapproved.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Remote access tool(s) found: ' + ($unapproved -join ', ') + '.') $out 'High' 'Remove the tool if it is not approved. If approved, use strong authentication, limit who can connect, and keep it updated.' ($pocR -join "`n") }
    else { Add-Check $Num $Name 'GOOD' 'No unapproved remote access tool found.' $out }
}

Invoke-Check 31 'AnyDesk details' {
    $svc = @(Get-Service | Where-Object { $_.Name -match 'anydesk' -or $_.DisplayName -match 'anydesk' })
    $exe = @("${env:ProgramFiles(x86)}\AnyDesk\AnyDesk.exe", "$env:ProgramFiles\AnyDesk\AnyDesk.exe") | Where-Object { Test-Path $_ }
    $app = @($sw | Where-Object { $_.DisplayName -match 'anydesk' })
    if ($svc.Count -eq 0 -and @($exe).Count -eq 0 -and $app.Count -eq 0) {
        Add-Check $Num $Name 'GOOD' 'AnyDesk is not installed.' '(not installed)'
        return
    }
    $sysConf = Join-Path $env:ProgramData 'AnyDesk\system.conf'
    $usrConf = Join-Path $env:APPDATA 'AnyDesk\user.conf'
    $trace   = Join-Path $env:ProgramData 'AnyDesk\connection_trace.txt'
    $pwdSet = $false
    $lines = @()
    foreach ($f in $sysConf, $usrConf) {
        if (Test-Path $f) {
            $c = @(Get-Content $f)
            if (@($c | Where-Object { $_ -match '^\s*ad\.security\.pwd_hash\s*=' }).Count -gt 0) { $pwdSet = $true }
            $lines += $c | Where-Object { $_ -match '^\s*ad\.' -and $_ -notmatch 'pwd|passw|hash|salt|key|token|cert|secret|id\s*=' }
        }
    }
    $conn = '(no connection log found)'
    if (Test-Path $trace) { $conn = (Get-Content $trace -Tail 15 | Out-String).Trim() }
    $out = "AnyDesk service: " + (($svc | ForEach-Object { "$($_.Name) = $($_.Status)" }) -join ', ') +
           "`nUnattended-access password found in config: $pwdSet`n`nSettings (passwords and keys hidden):`n" + (Fmt $lines -Empty '(no config lines read)') +
           "`n`nLast connections:`n$conn"
    if ($pwdSet) { Add-Check $Num $Name 'BAD' 'An unattended-access password appears to be set in the AnyDesk config. Anyone with the AnyDesk ID and password can connect without someone accepting.' $out 'High' 'Remove the unattended-access password, or use a strong one with an allow-list of approved AnyDesk IDs. Review the last connections below.' }
    else { Add-Check $Num $Name 'GOOD' 'No unattended-access password was found in the AnyDesk config. (Also verify in AnyDesk: Settings > Security.)' $out }
}

# =============================================================================
# GROUP G - Software and Persistence
# =============================================================================
$script:cat = 'Software and Persistence'

Invoke-Check 32 'Installed software' {
    $riskPat = 'utorrent|bittorrent|qbittorrent|vuze|emule|frostwire|limewire|flash player|shockwave'
    $risky = @()
    foreach ($s in $sw) {
        if ($s.DisplayName -match $riskPat) {
            $ok = $false
            foreach ($a in $ApprovedSoftware) { if ($s.DisplayName -like "*$a*") { $ok = $true } }
            if (-not $ok) { $risky += $s.DisplayName }
        }
    }
    $out = Fmt ($sw | Select-Object DisplayName, DisplayVersion, Publisher)
    if (-not $sw) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read the software list.' $out }
    elseif ($risky.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Risky or end-of-life software found: ' + ($risky -join ', ') + '.') $out 'Medium' 'Uninstall this software.' ($risky -join "`n") }
    else { Add-Check $Num $Name 'GOOD' 'No torrent/P2P or end-of-life software (such as Flash) found. Full list is below for reference.' $out }
}

Invoke-Check 33 'Startup programs' {
    $st = @(Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User)
    $hi = @(); $me = @(); $lo = @(); $flagged = @()
    foreach ($x in $st) {
        $cmd = [string]$x.Command
        $exe = Get-ExeOf $cmd
        $bad1 = ($cmd -match '-enc |-encodedcommand|mshta|certutil.*-(urlcache|decode)|bitsadmin.*/transfer|frombase64string|downloadstring')
        $tmp = ($exe -match '\\Windows\\Temp\\|\\AppData\\Local\\Temp\\|\\Users\\Public\\')
        if ($bad1) { $hi += $x.Name; $flagged += ($x.Name + '  ->  ' + $cmd) }
        elseif ($tmp) {
            $si = Get-SignInfo $exe
            if ($si.State -eq 'signed') { $me += $x.Name; $flagged += ($x.Name + '  ->  ' + $cmd + '   [file is digitally signed by: ' + $si.Signer + ']') }
            elseif ($si.State -eq 'unsigned') { $hi += $x.Name; $flagged += ($x.Name + '  ->  ' + $cmd + '   [file is NOT digitally signed]') }
            else { $lo += $x.Name; $flagged += ($x.Name + '  ->  ' + $cmd + '   [file not found on disk]') }
        }
        elseif (($exe -match '\\Downloads\\|\\ProgramData\\[^\\]+\.exe$') -or ($cmd -match 'wscript|cscript')) { $me += $x.Name; $flagged += ($x.Name + '  ->  ' + $cmd) }
    }
    $out = Fmt $st
    if ($st.Count -eq 0) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read startup programs (or there are none).' $out }
    elseif ($hi.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Suspicious startup item(s) (encoded or download command, or an unsigned program in a Temp/Public folder): ' + ($hi -join ', ') + '.') $out 'High' 'Check these items. Remove them if they are not approved software.' ($flagged -join "`n") }
    elseif ($me.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Startup item(s) that need a look (signed program in a Temp folder, script host, Downloads folder or ProgramData program): ' + ($me -join ', ') + '.') $out 'Medium' 'Check these items. Remove them if they are not approved software.' ($flagged -join "`n") }
    elseif ($lo.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Startup item(s) point to a file in a Temp/Public folder that no longer exists: ' + ($lo -join ', ') + '.') $out 'Low' 'Remove the leftover startup entries.' ($flagged -join "`n") }
    else { Add-Check $Num $Name 'GOOD' 'No startup item runs from Temp, Downloads or Public, or uses encoded or download commands.' $out }
}

Invoke-Check 34 'Scheduled tasks (non-Microsoft)' {
    $tasks = @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })
    $rows = @()
    foreach ($t in $tasks) {
        foreach ($ac in @($t.Actions)) {
            $rows += [pscustomobject]@{ Task = $t.TaskName; State = [string]$t.State; Run = ((("$($ac.Execute) $($ac.Arguments)")).Trim()); Exe = [string]$ac.Execute }
        }
    }
    $hi = @(); $me = @(); $lo = @(); $flagged = @()
    foreach ($r in $rows) {
        $run = [string]$r.Run
        $exe = Get-ExeOf ([string]$r.Exe)
        $bad1 = ($run -match '-enc |-encodedcommand|mshta|certutil.*-(urlcache|decode)|bitsadmin.*/transfer|frombase64string|downloadstring')
        $tmp = ($exe -match '\\Windows\\Temp\\|\\AppData\\Local\\Temp\\|\\Users\\Public\\')
        if ($bad1) { $hi += $r.Task; $flagged += ($r.Task + '  ->  ' + $run) }
        elseif ($tmp) {
            $si = Get-SignInfo $exe
            if ($si.State -eq 'signed') { $me += $r.Task; $flagged += ($r.Task + '  ->  ' + $run + '   [file is digitally signed by: ' + $si.Signer + ']') }
            elseif ($si.State -eq 'unsigned') { $hi += $r.Task; $flagged += ($r.Task + '  ->  ' + $run + '   [file is NOT digitally signed]') }
            else { $lo += $r.Task; $flagged += ($r.Task + '  ->  ' + $run + '   [file not found on disk]') }
        }
        elseif (($exe -match '\\Downloads\\|\\ProgramData\\[^\\]+\.exe$') -or ($run -match 'wscript|cscript')) { $me += $r.Task; $flagged += ($r.Task + '  ->  ' + $run) }
    }
    $out = Fmt ($rows | Select-Object Task, State, Run) -Empty '(no non-Microsoft tasks)'
    if ($hi.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Suspicious scheduled task(s) (encoded or download command, or an unsigned program in a Temp/Public folder): ' + (($hi | Select-Object -Unique) -join ', ') + '.') $out 'High' 'Check these tasks. Delete them if they are not approved.' ($flagged -join "`n") }
    elseif ($me.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Scheduled task(s) that need a look (signed program in a Temp folder, script host, Downloads folder or ProgramData program): ' + (($me | Select-Object -Unique) -join ', ') + '.') $out 'Medium' 'Check these tasks. Delete them if they are not approved.' ($flagged -join "`n") }
    elseif ($lo.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Scheduled task(s) point to a file in a Temp/Public folder that no longer exists: ' + (($lo | Select-Object -Unique) -join ', ') + '.') $out 'Low' 'Delete the leftover tasks.' ($flagged -join "`n") }
    else { Add-Check $Num $Name 'GOOD' 'No scheduled task runs a program from Temp, Downloads or Public, or uses encoded or download commands.' $out }
}

Invoke-Check 35 'Services (unsafe paths)' {
    $svcs = @(Get-CimInstance Win32_Service | Where-Object { $_.PathName })
    $unq = @(); $unqLow = @(); $wr = @()
    foreach ($x in $svcs) {
        $p = [string]$x.PathName
        if ($p -notmatch '^"' -and $p -match '(?i)\.exe') {
            $exe = ($p -split '(?i)\.exe')[0]
            if ($exe -match '\s') {
                # A path with spaces is only dangerous if a normal user can create a file in a folder Windows tries first
                $hit = $false
                $pos = 0
                while (($pos = $exe.IndexOf(' ', $pos)) -ge 0) {
                    $cand = $exe.Substring(0, $pos) + '.exe'
                    $dir = Split-Path $cand -Parent
                    if ($dir -and (Test-Path $dir) -and (Test-CanCreateFile $dir)) { $hit = $true; break }
                    $pos++
                }
                if ($hit) { $unq += $x.Name } else { $unqLow += $x.Name }
            }
        }
        if ((Get-ExeOf $p) -match '(?i)\\Users\\|\\Temp\\|\\Downloads\\') { $wr += $x.Name }
    }
    $out = "Total services checked: $($svcs.Count)`nUnquoted service paths that a normal user can exploit: " + ($unq -join ', ') + "`nUnquoted service paths that normal users cannot exploit: " + ($unqLow -join ', ') + "`nServices running from user or temp folders: " + ($wr -join ', ')
    $pocV = (@($svcs | Where-Object { (@($unq) + @($wr) + @($unqLow)) -contains $_.Name } | ForEach-Object { $_.Name + '  ->  ' + $_.PathName }) -join "`n")
    $bad = @(); $sv = 'Low'
    if ($wr.Count -gt 0) { $bad += ('Service(s) run from user/temp folders: ' + ($wr -join ', ') + '.'); $sv = 'High' }
    if ($unq.Count -gt 0) { $bad += ('Unquoted service path(s) that a normal user can use to gain higher rights: ' + ($unq -join ', ') + '.'); if ($sv -ne 'High') { $sv = 'Medium' } }
    if ($unqLow.Count -gt 0) { $bad += ('Unquoted service path(s) (not exploitable by normal users now): ' + ($unqLow -join ', ') + '.') }
    if ($svcs.Count -eq 0) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read services.' $out }
    elseif ($bad.Count -gt 0) { Add-Check $Num $Name 'BAD' ($bad -join ' ') $out $sv 'Put service paths in quotes. Check services that run from user or temp folders.' $pocV }
    else { Add-Check $Num $Name 'GOOD' 'No unquoted service paths and no service runs from user or temp folders.' $out }
}

Invoke-Check 36 'Legacy Windows features' {
    $names = 'MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2', 'TelnetClient', 'TFTP', 'SMB1Protocol', 'SMB1Protocol-Client', 'SMB1Protocol-Server'
    $feat = @(Get-WindowsOptionalFeature -Online | Where-Object { $names -contains $_.FeatureName })
    $on = @($feat | Where-Object { [string]$_.State -eq 'Enabled' })
    $out = Fmt ($feat | Select-Object FeatureName, State)
    if ($feat.Count -eq 0) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read Windows features (not available on this Windows edition).' $out }
    elseif ($on.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Old feature(s) are enabled: ' + (($on | ForEach-Object { $_.FeatureName }) -join ', ') + '.') $out 'Medium' 'Turn off PowerShell 2.0, Telnet client, TFTP and SMB1 in Windows Features.' (Fmt ($on | Select-Object FeatureName, State)) }
    else { Add-Check $Num $Name 'GOOD' 'PowerShell 2.0, Telnet, TFTP and SMB1 features are off.' $out }
}

# =============================================================================
# GROUP H - Logging
# =============================================================================
$script:cat = 'Logging'

Invoke-Check 37 'Event log size and audit policy' {
    $log = Get-WinEvent -ListLog Security
    $sizeMB = $null
    if ($log) { $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB) }
    $ap = @(auditpol /get /category:* /r 2>&1 | ConvertFrom-Csv)
    $guids = @{
        '{0CCE9215-69AE-11D9-BED3-505054503030}' = 'Logon'
        '{0CCE9217-69AE-11D9-BED3-505054503030}' = 'Account Lockout'
        '{0CCE922B-69AE-11D9-BED3-505054503030}' = 'Process Creation'
        '{0CCE9235-69AE-11D9-BED3-505054503030}' = 'User Account Management'
    }
    $rows = @()
    foreach ($row in $ap) {
        $g = [string]$row.'Subcategory GUID'
        if ($guids.ContainsKey($g)) { $rows += [pscustomobject]@{ Audit = $guids[$g]; Setting = [string]$row.'Inclusion Setting' } }
    }
    $logon = $rows | Where-Object { $_.Audit -eq 'Logon' } | Select-Object -First 1
    $out = "Security log maximum size: $sizeMB MB (retention mode: $($log.LogMode))`n`nAudit policy:`n" + (Fmt $rows -Empty '(audit policy could not be read)')
    $bad = @()
    if ($null -ne $sizeMB -and $sizeMB -lt 100) { $bad += "Security log is only $sizeMB MB (100 MB or more is recommended)." }
    if ($logon -and ($logon.Setting -notmatch 'Success and Failure')) { $bad += "Logon auditing is '$($logon.Setting)' (should be Success and Failure)." }
    if ($null -eq $sizeMB -and -not $logon) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read the Security log or audit policy.' $out }
    elseif ($bad.Count -gt 0) { Add-Check $Num $Name 'BAD' ($bad -join ' ') $out 'Low' 'Increase the Security log size and audit logon success and failure.' }
    else { Add-Check $Num $Name 'GOOD' 'Security log size and logon auditing are acceptable.' $out }
}

Invoke-Check 38 'PowerShell and command-line logging' {
    $sbl = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    $cmd = RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'
    $out = "PowerShell script block logging = $sbl   (1 = on)`nCommand line in process-creation events = $cmd   (1 = on)"
    $bad = @()
    if ($sbl -ne 1) { $bad += 'PowerShell script block logging is off.' }
    if ($cmd -ne 1) { $bad += 'Command-line logging for new processes is off.' }
    if ($bad.Count -gt 0) { Add-Check $Num $Name 'BAD' ($bad -join ' ') $out 'Low' 'Turn on script block logging and command-line logging by policy. They help investigate attacks.' }
    else { Add-Check $Num $Name 'GOOD' 'PowerShell and command-line logging are on.' $out }
}

# =============================================================================
# GROUP I - Web Server
# =============================================================================
$script:cat = 'Web Server'

Invoke-Check 39 'IIS web server' {
    $w3 = Get-Service W3SVC
    if (-not $w3) { Add-Check $Num $Name 'GOOD' 'IIS is not installed.' '(not installed)'; return }
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $sites = @(Get-Website)
    $binds = @(Get-WebBinding)
    $dirb = Get-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' -PSPath 'MACHINE/WEBROOT/APPHOST' -Name enabled
    $dirOn = $false
    if ($dirb) { $dirOn = [bool]$dirb.Value }
    $defPage = Test-Path "$env:SystemDrive\inetpub\wwwroot\iisstart.htm"
    $out = "W3SVC service: $($w3.Status)`n`nSites:`n" + (Fmt ($sites | Select-Object Name, State, PhysicalPath)) +
           "`n`nBindings:`n" + (Fmt ($binds | Select-Object protocol, bindingInformation)) +
           "`n`nDirectory browsing enabled: $dirOn`nDefault IIS start page present: $defPage"
    if ([string]$w3.Status -ne 'Running') { Add-Check $Num $Name 'GOOD' 'IIS is installed but not running.' $out; return }
    $bad = @()
    $http  = @($binds | Where-Object { [string]$_.protocol -eq 'http' })
    $https = @($binds | Where-Object { [string]$_.protocol -eq 'https' })
    if ($http.Count -gt 0 -and $https.Count -eq 0) { $bad += 'IIS serves HTTP only (no HTTPS binding).' }
    if ($dirOn) { $bad += 'Directory browsing is enabled.' }
    if ($defPage) { $bad += 'The default IIS start page is still present.' }
    if ($bad.Count -gt 0) { Add-Check $Num $Name 'BAD' ($bad -join ' ') $out 'Medium' 'Confirm the website owner and purpose. Use HTTPS, turn off directory browsing, remove the default page, and stop IIS if it is not needed.' }
    else { Add-Check $Num $Name 'GOOD' 'IIS uses HTTPS, directory browsing is off, and the default page is removed.' $out }
}

# =============================================================================
# GROUP J - Compromise Indicators
# =============================================================================
$script:cat = 'Compromise Indicators'

Invoke-Check 40 'Hosts file' {
    $hf = "$env:windir\System32\drivers\etc\hosts"
    if (-not (Test-Path $hf)) { Add-Check $Num $Name 'NOT CHECKED' 'Hosts file was not found.' '(missing)'; return }
    $act = @(Get-Content $hf | ForEach-Object { $_.Trim() } | Where-Object { $_ -and (-not $_.StartsWith('#')) })
    $odd = @($act | Where-Object { ($_ -notmatch '^(127\.0\.0\.1|::1)\s+localhost\s*(#.*)?$') -and ($_ -notmatch 'host\.docker\.internal|gateway\.docker\.internal|kubernetes\.docker\.internal') })
    $av = @($odd | Where-Object { $_ -match 'windowsupdate|update\.microsoft|delivery\.mp\.microsoft|defender|\b(kaspersky|avast|eset|mcafee|symantec|norton|sophos|bitdefender|malwarebytes|trendmicro|avira|webroot)\b' })
    $out = "Active lines: $($act.Count)`n" + ($act -join "`n")
    if ($av.Count -gt 0) { Add-Check $Num $Name 'BAD' 'The hosts file has entries for update or antivirus websites. Malware uses this to block updates.' $out 'High' 'Remove these lines from the hosts file and run a full malware scan.' }
    elseif ($odd.Count -gt 0) { Add-Check $Num $Name 'BAD' "The hosts file has $($odd.Count) custom entr(y/ies) besides localhost (this is only a note: custom entries are common)." $out 'Low' 'Check each line. Remove entries that are not approved.' }
    else { Add-Check $Num $Name 'GOOD' 'The hosts file only has the normal localhost entries.' $out }
}

Invoke-Check 41 'Proxy and DNS settings' {
    $ie  = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $pe  = $ie.ProxyEnable; $ps = $ie.ProxyServer; $pac = $ie.AutoConfigURL
    $wh  = (netsh winhttp show proxy 2>&1 | Out-String).Trim()
    $whProxy = ($wh -notmatch 'Direct access')
    $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses })
    $all = @($dns | ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique)
    $known = '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220'
    $unk = @($all | Where-Object { ($_ -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|169\.254\.)') -and ($known -notcontains $_) })
    $out = "User proxy enabled = $pe   Proxy server = $ps   PAC file = $pac`n`nSystem (WinHTTP) proxy:`n$wh`n`nDNS servers:`n" +
           (Fmt ($dns | Select-Object InterfaceAlias, @{ n = 'Servers'; e = { $_.ServerAddresses -join ', ' } }))
    $bad = @(); $sv = 'Low'
    if (-not $ProxyAllowed -and ($pe -eq 1 -or $pac -or $whProxy)) { $bad += 'A proxy or PAC file is set. Confirm with the client that it is approved (malware and interception tools also use this).'; if ([string]$ps -match '127\.0\.0\.1|localhost|\[::1\]') { $sv = 'Medium' } }
    if ($unk.Count -gt 0) { $bad += ('Unknown public DNS server(s): ' + ($unk -join ', ') + '. (ISP DNS may be normal; confirm with the client.)') }
    if ($bad.Count -gt 0) { Add-Check $Num $Name 'BAD' ($bad -join ' ') $out $sv 'Remove proxy settings that are not approved. Use only the DNS servers the client expects.' }
    else { Add-Check $Num $Name 'GOOD' 'No proxy is set, and DNS servers are private or well-known public resolvers.' $out }
}

Invoke-Check 42 'WMI persistence' {
    $cons = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer')
    $bad = @($cons | Where-Object { $_.CimClass.CimClassName -match 'CommandLineEventConsumer|ActiveScriptEventConsumer' })
    $out = Fmt ($cons | Select-Object Name, @{ n = 'Type'; e = { $_.CimClass.CimClassName } }) -Empty '(no WMI event consumers)'
    if ($bad.Count -gt 0) {
        $susW = @($bad | Where-Object { ([string]$_.CommandLineTemplate + ' ' + [string]$_.ScriptText) -match 'powershell|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil|http' })
        $svW = 'Medium'; if ($susW.Count -gt 0) { $svW = 'High' }
        Add-Check $Num $Name 'BAD' ('WMI event consumer(s) that run commands or scripts were found: ' + (($bad | ForEach-Object { $_.Name }) -join ', ') + '. Attackers use this to stay hidden.') $out $svW 'Investigate these consumers. Remove them if they are not from approved software.'
    }
    else { Add-Check $Num $Name 'GOOD' 'No WMI consumer that runs commands or scripts was found.' $out }
}

Invoke-Check 43 'Event log warning signs (last 30 days)' {
    $start = (Get-Date).AddDays(-30)
    $cleared = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102; StartTime = $start } -MaxEvents 50) +
               @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 104; StartTime = $start } -MaxEvents 50)
    $newUser = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4720; StartTime = $start } -MaxEvents 200)
    $adminAdd = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4732; StartTime = $start } -MaxEvents 500 | Where-Object {
        $x = [xml]$_.ToXml()
        @($x.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetSid' -and $_.'#text' -eq 'S-1-5-32-544' }).Count -gt 0
    })
    $failed = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $start } -MaxEvents 5000)
    $lock = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4740; StartTime = $start } -MaxEvents 200)
    $flagEv = @($cleared + $newUser + $adminAdd) | Sort-Object TimeCreated -Descending | Select-Object -First 15 TimeCreated, Id, ProviderName
    $out = "Event log cleared: $($cleared.Count)`nNew local user created (4720): $($newUser.Count)`nUser added to Administrators (4732): $($adminAdd.Count)`nFailed logons (4625): $($failed.Count)`nAccount lockouts (4740): $($lock.Count)`n`nRecent important events:`n" + (Fmt $flagEv -Empty '(none)')
    $bad = @(); $sv = 'Low'
    if ($cleared.Count -gt 0) { $bad += "An event log was cleared $($cleared.Count) time(s)."; $sv = 'High' }
    if ($adminAdd.Count -gt 0) { $bad += "$($adminAdd.Count) user(s) were added to the Administrators group." }
    if ($newUser.Count -gt 0) { $bad += "$($newUser.Count) new local user account(s) were created." }
    if ($failed.Count -ge 50) { $bad += "$($failed.Count) failed logons (possible password guessing)."; if ($sv -ne 'High') { $sv = 'Medium' } }
    if ($lock.Count -gt 0) { $bad += "$($lock.Count) account lockout(s)." }
    if ($bad.Count -gt 0) { Add-Check $Num $Name 'BAD' ($bad -join ' ') $out $sv 'Check who did these actions and when. Confirm they were approved. Keep the logs as evidence.' }
    else { Add-Check $Num $Name 'GOOD' 'No log clearing, new admin, new user or heavy failed-logon activity in the last 30 days. (If auditing is off, see check 37, these events are not recorded.)' $out }
}

Invoke-Check 44 'Traffic interception certificates' {
    $rx = 'Fiddler|Burp|PortSwigger|mitmproxy|Charles Proxy|DO_NOT_TRUST|Proxyman|Wireshark'
    $certs = @(Get-ChildItem Cert:\LocalMachine\Root) + @(Get-ChildItem Cert:\CurrentUser\Root)
    $hit = @($certs | Where-Object { $_.Subject -match $rx -or $_.Issuer -match $rx })
    $out = "Trusted root certificates checked: $($certs.Count)`n`nSuspicious certificates:`n" + (Fmt ($hit | Select-Object Subject, Thumbprint, NotAfter) -Empty '(none)')
    if ($certs.Count -eq 0) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read the certificate store.' $out }
    elseif ($hit.Count -gt 0) { Add-Check $Num $Name 'BAD' 'A root certificate from a traffic interception tool (Fiddler, Burp, mitmproxy, etc.) is trusted on this PC. It can be used to read HTTPS traffic.' $out 'High' 'Remove these certificates if they are not needed for approved testing.' }
    else { Add-Check $Num $Name 'GOOD' 'No known interception-tool root certificate found. (Unknown company inspection certificates cannot be judged by a script.)' $out }
}

Invoke-Check 45 'Suspicious running programs' {
    $procs = @(Get-CimInstance Win32_Process)
    $rx1 = '\\Temp\\|\\Downloads\\|\\Users\\Public\\'
    $rx2 = '^(mimikatz|ncat|nc|netcat|psexec|psexec64|psexesvc|procdump|procdump64|meterpreter|cobaltstrike|beacon|xmrig|minerd|lazagne|rubeus|sharphound|bloodhound)(\.exe)?$'
    $hi = @($procs | Where-Object { [string]$_.Name -match $rx2 })
    $lo0 = @($procs | Where-Object { [string]$_.ExecutablePath -match $rx1 })
    $lo = @($lo0 | Where-Object { $sg = Get-AuthenticodeSignature -FilePath ([string]$_.ExecutablePath); [string]$sg.Status -ne 'Valid' })
    $flag = @($hi + $lo) | Select-Object -Unique Name, ProcessId, ExecutablePath
    $out = "Running processes checked: $($procs.Count)`n`nFlagged:`n" + (Fmt $flag -Empty '(none)')
    $crit = @($hi | Where-Object { [string]$_.Name -match '^(mimikatz|meterpreter|cobaltstrike|beacon|xmrig|minerd|lazagne|rubeus|sharphound|bloodhound)(\.exe)?$' })
    $svH = 'High'; if ($crit.Count -gt 0) { $svH = 'Critical' }
    if ($procs.Count -eq 0) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read running processes.' $out }
    elseif ($hi.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Hacking or miner tool names are running: ' + (($hi | ForEach-Object { $_.Name }) -join ', ') + '.') $out $svH 'Investigate immediately. Check who started these programs.' }
    elseif ($lo.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Program(s) without a valid digital signature are running from Temp, Downloads or Public folders: ' + (($lo | ForEach-Object { $_.Name } | Select-Object -Unique) -join ', ') + '.') $out 'Medium' 'Check these programs. Malware often runs from these folders.' }
    else { Add-Check $Num $Name 'GOOD' 'No known hacking tool names, and nothing runs from Temp, Downloads or Public folders.' $out }
}

# =============================================================================
# GROUP K - Extra Hardening
# =============================================================================
$script:cat = 'Extra Hardening'

Invoke-Check 46 'Browser extensions (Chrome and Edge)' {
    $rows = @(); $risky = @()
    $users = @(Get-ChildItem "$env:SystemDrive\Users" -Directory)
    foreach ($u in $users) {
        foreach ($b in 'Google\Chrome', 'Microsoft\Edge') {
            $ud = Join-Path $u.FullName "AppData\Local\$b\User Data"
            if (-not (Test-Path $ud)) { continue }
            foreach ($prof in @(Get-ChildItem $ud -Directory | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })) {
                $ed = Join-Path $prof.FullName 'Extensions'
                if (-not (Test-Path $ed)) { continue }
                foreach ($e in @(Get-ChildItem $ed -Directory)) {
                    $ver = Get-ChildItem $e.FullName -Directory | Sort-Object Name -Descending | Select-Object -First 1
                    if (-not $ver) { continue }
                    $mf = Join-Path $ver.FullName 'manifest.json'
                    if (-not (Test-Path $mf)) { continue }
                    $m = $null
                    try { $m = Get-Content $mf -Raw -ErrorAction Stop | ConvertFrom-Json } catch { }
                    if (-not $m) { continue }
                    $nm = [string]$m.name
                    if ($nm -like '__MSG_*') {
                        $key = ($nm -replace '^__MSG_', '' -replace '__$', '')
                        $resolved = ''
                        foreach ($lc in @([string]$m.default_locale, 'en', 'en_US', 'en_GB')) {
                            if (-not $lc) { continue }
                            $lf = Join-Path $ver.FullName ('_locales\' + $lc + '\messages.json')
                            if (Test-Path -LiteralPath $lf) {
                                try {
                                    $lj = Get-Content -LiteralPath $lf -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
                                    $ent = $lj.PSObject.Properties | Where-Object { $_.Name -ieq $key } | Select-Object -First 1
                                    if ($ent) { $resolved = [string]$ent.Value.message }
                                } catch { }
                            }
                            if ($resolved) { break }
                        }
                        if ($resolved) { $nm = $resolved } else { $nm = '(name not readable)' }
                    }
                    $perm = @(@($m.permissions) + @($m.host_permissions) | ForEach-Object { [string]$_ })
                    $allUrls = ($perm -contains '<all_urls>') -or (@($perm | Where-Object { $_ -match '^(\*|https?|http\*)://\*/\*$' }).Count -gt 0)
                    $danger = @($perm | Where-Object { $_ -match '^(cookies|nativeMessaging|webRequestBlocking|debugger|proxy|management)$' })
                    $isRisky = ($allUrls -and ($danger.Count -gt 0))
                    $rows += [pscustomobject]@{ User = $u.Name; Browser = ($b -replace '.*\\', ''); Extension = $nm; Id = $e.Name; Version = [string]$m.version; Risky = $isRisky }
                    if ($isRisky) { $risky += "$nm ($($e.Name))" }
                }
            }
        }
    }
    $out = Fmt $rows -Empty '(no Chrome or Edge extensions found)'
    if ($risky.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Extension(s) can read all websites and also use powerful permissions (cookies, proxy, native apps): ' + ($risky -join '; ') + '.') $out 'Low' 'Remove extensions that are not approved. Allow only needed extensions.' (Fmt ($rows | Where-Object { $_.Risky } | Select-Object Browser, Extension, Id, Version)) }
    else { Add-Check $Num $Name 'GOOD' 'No extension combines access to all websites with powerful permissions. Extension list is below for reference.' $out }
}

Invoke-Check 47 'Saved credentials' {
    $raw = (cmdkey /list 2>&1 | Out-String)
    $targets = @($raw -split "`r?`n" | Where-Object { $_ -match 'Target:' } | ForEach-Object { $_.Trim() })
    $rdp = @($targets | Where-Object { $_ -match 'TERMSRV' })
    $out = "Saved credential targets (passwords are not shown):`n" + ($targets -join "`n")
    if ($rdp.Count -gt 0) { Add-Check $Num $Name 'BAD' "$($rdp.Count) saved Remote Desktop credential(s) found. Anyone using this account can connect to those servers without a password." $out 'Medium' 'Remove saved RDP credentials in Credential Manager.' ($rdp -join "`n") }
    else { Add-Check $Num $Name 'GOOD' 'No saved Remote Desktop credentials found for the user running this script.' $out }
}

Invoke-Check 48 'Saved Wi-Fi networks' {
    $prof = (netsh wlan show profiles 2>&1 | Out-String)
    $names = @([regex]::Matches($prof, 'All User Profile\s*:\s*(.+)') | ForEach-Object { $_.Groups[1].Value.Trim() })
    $open = @(); $rows = @()
    foreach ($n in $names) {
        $d = (& netsh wlan show profile ('name=' + $n) 2>&1 | Out-String)
        $auth = ''
        if ($d -match 'Authentication\s*:\s*(\S+)') { $auth = $Matches[1] }
        $rows += [pscustomobject]@{ Profile = $n; Authentication = $auth }
        if ($auth -eq 'Open') { $open += $n }
    }
    $out = Fmt $rows -Empty '(no saved Wi-Fi profiles, or no Wi-Fi adapter)'
    if ($open.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Saved open (no password) Wi-Fi network(s): ' + ($open -join ', ') + '. The PC may join them automatically.') $out 'Low' 'Remove open Wi-Fi profiles. Use only protected networks.' (($open | ForEach-Object { $_ + '   (security: Open, no password)' }) -join "`n") }
    else { Add-Check $Num $Name 'GOOD' 'No saved open Wi-Fi networks.' $out }
}

Invoke-Check 49 'SmartScreen and ransomware protection' {
    $cfa = $null
    if ($mpPref) { $cfa = $mpPref.EnableControlledFolderAccess }
    $ss = RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'
    $ssPol = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
    $out = "SmartScreenEnabled = $ss   (Off = bad)`nSmartScreen policy (EnableSmartScreen) = $ssPol   (0 = off)`nControlled Folder Access = $cfa   (1 = on, 2 = audit, 0 = off)"
    $bad = @(); $sv = 'Low'
    if ([string]$ss -eq 'Off' -or $ssPol -eq 0) { $bad += 'SmartScreen is turned off.'; $sv = 'Medium' }
    if ($null -ne $cfa -and $cfa -eq 0) { $bad += 'Controlled Folder Access (ransomware protection) is off.' }
    if ($bad.Count -gt 0) { Add-Check $Num $Name 'BAD' ($bad -join ' ') $out $sv 'Turn on SmartScreen and Controlled Folder Access in Windows Security.' }
    else { Add-Check $Num $Name 'GOOD' 'SmartScreen is on and Controlled Folder Access is not turned off.' $out }
}

Invoke-Check 50 'Application control (AppLocker / WDAC)' {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard
    $wdac = $dg.CodeIntegrityPolicyEnforcementStatus
    $umci = $dg.UsermodeCodeIntegrityPolicyEnforcementStatus
    $ap = Get-AppLockerPolicy -Effective
    $cnt = 0
    if ($ap) { foreach ($rc in $ap.RuleCollections) { $cnt += @($rc).Count } }
    $out = "WDAC kernel policy status = $wdac   (2 = enforced)`nWDAC user-mode policy status = $umci   (2 = enforced)`nAppLocker rules = $cnt"
    if ($wdac -eq 2 -or $umci -eq 2 -or $cnt -gt 0) { Add-Check $Num $Name 'GOOD' 'Application control (WDAC or AppLocker) is in use.' $out }
    else { Add-Check $Num $Name 'BAD' 'No application control (AppLocker or WDAC) is set, so any program can run.' $out 'Low' 'Use AppLocker or WDAC to allow only approved programs, if the client policy requires it.' }
}

Invoke-Check 51 'Memory protections (HVCI and DEP)' {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard
    $hvci = @($dg.SecurityServicesRunning) -contains 2
    $dep = (Get-CimInstance Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy
    $out = "Memory integrity (HVCI) running: $hvci`nVirtualization-based security status = $($dg.VirtualizationBasedSecurityStatus)   (2 = running)`nDEP policy = $dep   (0 = off, 1 = all on, 2 = Windows only, 3 = opt-out)"
    $bad = @(); $sv = 'Low'
    if ($null -ne $dep -and $dep -eq 0) { $bad += 'DEP (data execution prevention) is off.'; $sv = 'Medium' }
    if (-not $hvci) { $bad += 'Memory integrity (HVCI) is not running.' }
    if ($bad.Count -gt 0) { Add-Check $Num $Name 'BAD' ($bad -join ' ') $out $sv 'Turn on Memory integrity in Windows Security > Device security > Core isolation. Keep DEP on.' }
    else { Add-Check $Num $Name 'GOOD' 'Memory integrity is running and DEP is on.' $out }
}

Invoke-Check 52 'BIOS / firmware age' {
    $rd = $bios.ReleaseDate
    if (-not $rd) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read the BIOS date.' '(no data)'; return }
    $years = [math]::Round(((Get-Date) - [datetime]$rd).TotalDays / 365.25, 1)
    $out = "BIOS vendor: $($bios.Manufacturer)`nBIOS version: $($bios.SMBIOSBIOSVersion)`nBIOS date: $rd  ($years years old)"
    if ($years -gt 3) { Add-Check $Num $Name 'BAD' "The BIOS is $years years old. Old firmware can have known security bugs." $out 'Low' 'Check the PC maker website for a BIOS update.' }
    else { Add-Check $Num $Name 'GOOD' "The BIOS is $years years old." $out }
}

Invoke-Check 53 'Print Spooler' {
    $sp = Get-Service Spooler
    $isServer = ([string]$osAll.Caption -match 'Server')
    $out = "Print Spooler service: $($sp.Status) ($($sp.StartType))`nWindows Server: $isServer`nDomain role number: $($cs.DomainRole)   (4 or 5 = domain controller)"
    if (-not $sp) { Add-Check $Num $Name 'GOOD' 'Print Spooler is not installed.' $out }
    elseif ([string]$sp.Status -ne 'Running') { Add-Check $Num $Name 'GOOD' 'Print Spooler is not running.' $out }
    elseif ($cs.DomainRole -ge 4) { Add-Check $Num $Name 'BAD' 'Print Spooler is running on a domain controller.' $out 'High' 'Disable Print Spooler on domain controllers.' }
    elseif ($isServer) { Add-Check $Num $Name 'BAD' 'Print Spooler is running on a server.' $out 'Medium' 'Disable Print Spooler on servers that do not print.' }
    else { Add-Check $Num $Name 'GOOD' 'Print Spooler is running on a normal PC. (Fine if the PC prints. Disable it if printing is not needed.)' $out }
}

Invoke-Check 54 'PowerShell execution policy' {
    $mpol = [string](Get-ExecutionPolicy -Scope MachinePolicy)
    $lm = [string](Get-ExecutionPolicy -Scope LocalMachine)
    $cu = [string](Get-ExecutionPolicy -Scope CurrentUser)
    $out = "MachinePolicy = $mpol`nLocalMachine = $lm`nCurrentUser = $cu`n(The Process scope is ignored, because this script uses Bypass for itself.)"
    $weak = @($mpol, $lm, $cu | Where-Object { $_ -in 'Unrestricted', 'Bypass' })
    if ($weak.Count -gt 0) { Add-Check $Num $Name 'BAD' 'PowerShell execution policy is Unrestricted or Bypass.' $out 'Low' 'Set the policy to RemoteSigned or AllSigned.' }
    else { Add-Check $Num $Name 'GOOD' 'PowerShell execution policy is not Unrestricted or Bypass.' $out }
}

Invoke-Check 55 'Privilege escalation weaknesses' {
    $issues = @(); $sv = 'Medium'; $lines = @()
    foreach ($d in "$env:SystemDrive\Program Files", "$env:SystemDrive\Program Files (x86)", $env:windir, "$env:windir\System32") {
        if (Test-Path $d) {
            $w = Test-UserWritable $d
            $lines += "Normal users can write to ${d}: $w"
            if ($w) { $issues += "Normal users can write to $d."; $sv = 'High' }
        }
    }
    $pathBad = @()
    $mp = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    foreach ($p in ($mp -split ';' | Where-Object { $_ })) {
        $ep = [Environment]::ExpandEnvironmentVariables($p)
        if ((Test-Path $ep) -and (Test-UserWritable $ep)) { $pathBad += $ep }
    }
    $lines += 'System PATH folders that normal users can write to: ' + ($pathBad -join '; ')
    if ($pathBad.Count -gt 0) { $issues += ('System PATH folder(s) writable by normal users: ' + ($pathBad -join '; ') + '.') }
    $aieM = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    $aieU = RegVal 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    $lines += "AlwaysInstallElevated: machine = $aieM, user = $aieU   (both 1 = bad)"
    if ($aieM -eq 1 -and $aieU -eq 1) { $issues += 'AlwaysInstallElevated is on (any user can install programs as SYSTEM).'; $sv = 'High' }
    $unaAll = @("$env:windir\Panther\unattend.xml", "$env:windir\Panther\Unattend\Unattend.xml", "$env:windir\System32\Sysprep\unattend.xml", "$env:windir\System32\Sysprep\Panther\unattend.xml", "$env:SystemDrive\unattend.xml", "$env:SystemDrive\sysprep.inf") | Where-Object { Test-Path $_ }
    $una = @()
    foreach ($uf in @($unaAll)) {
        $txt = ''
        try { $txt = [string](Get-Content -Path $uf -Raw -ErrorAction Stop) } catch { }
        if ($uf -match '\.inf$') {
            if ($txt -match '(?im)^\s*AdminPassword\s*=\s*\S') { $una += $uf }
        } elseif ($txt -match '(?is)<(Password|AdministratorPassword)\b[^>]*>\s*<Value>(?!\s*\*SENSITIVE\*DATA\*DELETED\*)[^<\s][^<]*</Value>') { $una += $uf }
    }
    $lines += 'Setup files found: ' + (@($unaAll) -join '; ')
    $lines += 'Setup files that still hold a password value (value not shown): ' + (@($una) -join '; ')
    if (@($una).Count -gt 0) { $issues += ('Leftover Windows setup file(s) that still contain a password value: ' + (@($una) -join '; ') + '.') }
    $out = $lines -join "`n"
    if ($issues.Count -gt 0) { Add-Check $Num $Name 'BAD' ($issues -join ' ') $out $sv 'Remove write access for normal users on these folders, turn off AlwaysInstallElevated, and delete leftover setup files after checking them.' ($issues -join "`n") }
    else { Add-Check $Num $Name 'GOOD' 'No writable system folders, no writable PATH folders, no AlwaysInstallElevated, and no leftover setup files.' $out }
}

Invoke-Check 56 'Remote Assistance' {
    $v = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp'
    $un = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowUnsolicited'
    $out = "fAllowToGetHelp = $v   (1 = Remote Assistance allowed, needs an invitation from the user)`nfAllowUnsolicited (Offer Remote Assistance policy) = $un   (1 = a helper can connect without an invitation)"
    if ($un -eq 1) { Add-Check $Num $Name 'BAD' 'Offer Remote Assistance is turned on: a helper can connect without an invitation.' $out 'Medium' 'Turn off the Offer Remote Assistance policy if it is not used.' }
    elseif ($v -eq 1) { Add-Check $Num $Name 'BAD' 'Windows Remote Assistance is allowed (invitation only). This is the Windows default.' $out 'Low' 'Turn it off if it is not used.' }
    else { Add-Check $Num $Name 'GOOD' 'Windows Remote Assistance is not allowed.' $out }
}

Invoke-Check 57 'Office macro security' {
    $installed = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration') -or (@($sw | Where-Object { $_.DisplayName -match 'Microsoft (Office|365)' }).Count -gt 0)
    if (-not $installed) { Add-Check $Num $Name 'GOOD' 'Microsoft Office is not installed.' '(not installed)'; return }
    $issues = @(); $lines = @()
    foreach ($app in 'Word', 'Excel', 'PowerPoint', 'Outlook') {
        foreach ($root in "HKCU:\Software\Policies\Microsoft\Office\16.0\$app\Security", "HKCU:\Software\Microsoft\Office\16.0\$app\Security") {
            $vba = RegVal $root 'VBAWarnings'
            $blk = RegVal $root 'BlockContentExecutionFromInternet'
            if ($null -ne $vba -or $null -ne $blk) {
                $lines += "$root : VBAWarnings = $vba (1 = all macros on), BlockContentExecutionFromInternet = $blk (0 = off)"
                if ($vba -eq 1) { $issues += "$app allows all macros without asking." }
                if ($blk -eq 0) { $issues += "$app does not block macros from the internet." }
            }
        }
    }
    $out = Fmt $lines -Empty '(no explicit macro settings found, so Office defaults apply)'
    if ($lines.Count -gt 0) { $out = $lines -join "`n" }
    if ($issues.Count -gt 0) { Add-Check $Num $Name 'BAD' ($issues -join ' ') $out 'High' 'Set macros to "Disable all with notification" (or block them), and block macros from the internet.' }
    else { Add-Check $Num $Name 'GOOD' 'No Office app is set to allow all macros or to allow internet macros.' $out }
}

Invoke-Check 58 'Last malware scan' {
    if (-not $mpStatus) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read Defender scan history (a third-party antivirus may be in control).' '(no data)'; return }
    $q = $mpStatus.QuickScanAge; $f = $mpStatus.FullScanAge
    $out = "Quick scan: last finished $($mpStatus.QuickScanEndTime)  ($q days ago)`nFull scan: last finished $($mpStatus.FullScanEndTime)  ($f days ago)`n(4294967295 days = never)"
    if ($q -gt 14 -and $f -gt 30) { Add-Check $Num $Name 'BAD' 'No quick scan in the last 14 days and no full scan in the last 30 days.' $out 'Low' 'Run a full Defender scan now and schedule regular scans.' }
    else { Add-Check $Num $Name 'GOOD' 'A recent quick or full scan exists.' $out }
}

# =============================================================================
# GROUP 12 - Malware evidence, end-of-life and risky software
# =============================================================================

# One shared, shallow file scan of the user folders (names only, file contents are never read)
$userFiles = @()
foreach ($uu in @(Get-ChildItem "$env:SystemDrive\Users" -Directory)) {
    # Desktop/Documents are often moved into OneDrive (C:\Users\name\OneDrive\Desktop), so scan those too
    $roots = @($uu.FullName) + @(Get-ChildItem -LiteralPath $uu.FullName -Directory -Filter 'OneDrive*' | ForEach-Object { $_.FullName })
    foreach ($root in $roots) {
        foreach ($sub in 'Downloads', 'Desktop', 'Documents') {
            $dir = Join-Path $root $sub
            if (-not (Test-Path -LiteralPath $dir)) { continue }
            $userFiles += @(Get-ChildItem -LiteralPath $dir -Recurse -Depth 2 -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match '^\.(exe|msi|zip|rar|7z|iso|ps1|dll|txt|doc|docx|xls|xlsx|csv|rtf|odt|ods)$' })
        }
    }
}

Invoke-Check 59 'Malware detections (Defender history)' {
    if (-not $mpStatus) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read Defender detection history (a third-party antivirus may be in control).' '(no data)'; return }
    $threats = @{}
    foreach ($t in @(Get-MpThreat)) { $threats[[string]$t.ThreatID] = $t }
    $since = (Get-Date).AddDays(-90)
    $rows = @()
    foreach ($d in @(Get-MpThreatDetection)) {
        if ((-not $d.InitialDetectionTime) -or ($d.InitialDetectionTime -lt $since)) { continue }
        $t = $threats[[string]$d.ThreatID]
        $nm = ''; $act = $false
        if ($t) { $nm = [string]$t.ThreatName; $act = [bool]$t.IsActive }
        if ($nm -match 'EICAR') { continue }
        if (-not $nm) { $nm = 'ThreatID ' + [string]$d.ThreatID }
        $res = (@($d.Resources | ForEach-Object { [string]$_ }) -join '; ')
        $rows += [pscustomobject]@{ When = $d.InitialDetectionTime; Threat = $nm; Resource = $res; Active = $act }
    }
    $rows = @($rows | Sort-Object When -Descending)
    $active = @($rows | Where-Object { $_.Active })
    $recent = @($rows | Where-Object { $_.When -gt (Get-Date).AddDays(-30) })
    $lines = @()
    foreach ($r in $rows) {
        $st = 'removed'; if ($r.Active) { $st = 'STILL ACTIVE' }
        $lines += ($r.When.ToString('dd MMM yyyy') + '  |  ' + $r.Threat + '  |  ' + $r.Resource + '  |  ' + $st)
    }
    $out = '(no malware detections in the last 90 days)'
    if ($lines.Count -gt 0) { $out = $lines -join "`n" }
    $names = ((@($rows | ForEach-Object { $_.Threat } | Select-Object -Unique | Select-Object -First 5)) -join ', ')
    if ($active.Count -gt 0) {
        Add-Check $Num $Name 'BAD' ("Defender reports $($active.Count) threat(s) that are STILL ACTIVE (not removed): $($names).") $out 'Critical' 'Run a full Defender scan (or an Offline scan) now and remove the threats. Treat the PC as infected until it is clean, and change the passwords used on it.' $out
    } elseif ($recent.Count -gt 0) {
        Add-Check $Num $Name 'BAD' ("Defender detected $($recent.Count) threat(s) in the last 30 days (removed): $($names). The PC was exposed to malware.") $out 'Medium' 'Find out how it got in (download, USB, email). Run a full scan and check the startup items and scheduled tasks.' $out
    } elseif ($rows.Count -gt 0) {
        Add-Check $Num $Name 'BAD' ("Defender detected $($rows.Count) threat(s) 30 to 90 days ago (removed): $($names).") $out 'Low' 'Run a full scan to confirm the PC is clean.' $out
    } else {
        Add-Check $Num $Name 'GOOD' 'No malware detection recorded by Defender in the last 90 days. (A third-party antivirus keeps its own history.)' $out
    }
}

Invoke-Check 60 'End-of-life software' {
    $now = Get-Date
    $offEnd = @{ '2003' = '2014-04-08'; '2007' = '2017-10-10'; '2010' = '2020-10-13'; '2013' = '2023-04-11'; '2016' = '2025-10-14'; '2019' = '2025-10-14'; '2021' = '2026-10-13' }
    $rules = @(
        @{ Rx = '^Adobe Flash Player'; End = '2020-12-31' },
        @{ Rx = '^Microsoft Silverlight'; End = '2021-10-12' },
        @{ Rx = '^Python 2\.'; End = '2020-01-01' },
        @{ Rx = '^Java(\(TM\))?( SE Development Kit)? (6|7)( Update|\s|$)'; End = '2015-04-14' },
        @{ Rx = '^Microsoft SQL Server (2008 R2|2008) \((64|32)-bit\)'; End = '2019-07-09' },
        @{ Rx = '^Microsoft SQL Server 2012 \((64|32)-bit\)'; End = '2022-07-12' },
        @{ Rx = '^Microsoft SQL Server 2014 \((64|32)-bit\)'; End = '2024-07-09' },
        @{ Rx = '^Microsoft SQL Server 2016 \((64|32)-bit\)'; End = '2026-07-14' }
    )
    $found = @()
    foreach ($s in $sw) {
        $dn = [string]$s.DisplayName
        if ($dn -match '^Microsoft Office\s+(Professional|Standard|Home|Small Business|Enterprise|Personal|Basic|Student|LTSC)[^0-9]*(2003|2007|2010|2013|2016|2019|2021)\b') {
            $end = [datetime]$offEnd[$Matches[2]]
            if ($now -gt $end) { $found += [pscustomobject]@{ Software = $dn; Version = [string]$s.DisplayVersion; Ended = $end } }
            continue
        }
        foreach ($rule in $rules) {
            if ($dn -match $rule.Rx) {
                $end = [datetime]$rule.End
                if ($now -gt $end) { $found += [pscustomobject]@{ Software = $dn; Version = [string]$s.DisplayVersion; Ended = $end } }
                break
            }
        }
    }
    $found = @($found | Sort-Object Software -Unique)
    $lines = @($found | ForEach-Object { $_.Software + '   ' + $_.Version + '   - support ended ' + $_.Ended.ToString('dd MMM yyyy') })
    $out = '(no end-of-life software found in the list this script knows)'
    if ($lines.Count -gt 0) { $out = $lines -join "`n" }
    $old = @($found | Where-Object { $_.Ended -lt $now.AddDays(-365) })
    $sv = 'Medium'; if ($old.Count -gt 0) { $sv = 'High' }
    if (-not $sw) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read the software list.' '(no data)' }
    elseif ($found.Count -gt 0) { Add-Check $Num $Name 'BAD' ("$($found.Count) installed program(s) no longer get security updates: " + (($found | ForEach-Object { $_.Software }) -join '; ') + '.') $out $sv 'Upgrade to a supported version, or remove the software.' $out }
    else { Add-Check $Num $Name 'GOOD' 'No end-of-life Office, SQL Server, Java 6/7, Python 2, Flash or Silverlight found. (Only the products this script knows are checked.)' $out }
}

Invoke-Check 61 'Pirated software and hacking tools' {
    # Strong names (installed programs, services, tasks, running programs)
    $crackRx = '\b(KMSpico|KMSAuto|AutoKMS|KMS[ _-]?(Activator|Tools?|Pico)|Microsoft Toolkit|Re-?Loader[ _-]?Activator|HWID ?Gen|AAct|MAS_AIO)\b'
    # File names in the user folders (also keygen / crack words; ssh-keygen is a normal tool)
    $crackFileRx = '\b(KMSpico|KMSAuto|AutoKMS|KMS[ _-]?(Activator|Tools?|Pico)|Microsoft Toolkit|Re-?Loader[ _-]?Activator|HWID ?Gen|AAct|MAS_AIO)\b|(?<!ssh-)keygen|\bcracked?\b'
    $hackFileRx = '^(mimikatz|lazagne|rubeus|sharphound|bloodhound|metasploit|meterpreter|hashcat|pwdump|fgdump|gsecdump|nbtscan)'
    $strong = @()
    foreach ($s in $sw) { if ([string]$s.DisplayName -match $crackRx) { $strong += ('Installed program: ' + $s.DisplayName) } }
    foreach ($v in @(Get-CimInstance Win32_Service)) { if (([string]$v.Name -match $crackRx) -or ([string]$v.DisplayName -match $crackRx)) { $strong += ('Service: ' + $v.DisplayName) } }
    foreach ($t in @(Get-ScheduledTask)) { if ([string]$t.TaskName -match $crackRx) { $strong += ('Scheduled task: ' + $t.TaskName) } }
    foreach ($pr in @(Get-Process)) { if ([string]$pr.ProcessName -match $crackRx) { $strong += ('Running program: ' + $pr.ProcessName) } }
    $weak = @()
    foreach ($f in $userFiles) {
        if ($f.Extension -notmatch '^\.(exe|msi|zip|rar|7z|iso|ps1|dll)$') { continue }
        if ($f.BaseName -match $crackFileRx) { $weak += ('File (crack/activator name): ' + $f.FullName) }
        elseif ($f.Name -match $hackFileRx) { $weak += ('File (hacking tool name): ' + $f.FullName) }
    }
    $all = @($strong) + @($weak)
    $out = '(none found)'
    if ($all.Count -gt 0) { $out = $all -join "`n" }
    if ($strong.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Pirated-software or activator tools are installed or running (' + $strong.Count + ' item(s)). These are a common way malware gets in.') $out 'High' 'Remove the cracked software and activators. Use properly licensed software, and scan the PC for malware.' $out }
    elseif ($weak.Count -gt 0) { Add-Check $Num $Name 'BAD' ('File(s) in the user folders have crack, activator or hacking-tool names (' + $weak.Count + ' file(s)). File contents were not checked.') $out 'Medium' 'Check these files. Delete them if they are not approved.' $out }
    else { Add-Check $Num $Name 'GOOD' 'No crack, activator or hacking-tool names found in installed programs, services, tasks, running programs or the Downloads, Desktop and Documents folders.' $out }
}

Invoke-Check 62 'Software with known security flaws' {
    $rules = @(
        @{ Rx = '^WinRAR'; Fixed = '7.13'; Cve = 'CVE-2025-6218 and CVE-2025-8088 (file extraction flaws, actively attacked)'; Sev = 'High' },
        @{ Rx = '^7-Zip'; Fixed = '25.00'; Cve = 'CVE-2025-0411, CVE-2025-11001 and CVE-2025-11002 (file extraction flaws)'; Sev = 'High' },
        @{ Rx = '^PuTTY'; Fixed = '0.81'; Cve = 'CVE-2024-31497 (private key can be recovered)'; Sev = 'Medium' }
    )
    $found = @(); $sv = 'Medium'
    foreach ($s in $sw) {
        foreach ($rule in $rules) {
            if ([string]$s.DisplayName -match $rule.Rx) {
                $vs = ([string]$s.DisplayVersion -replace '[^0-9.].*$', '')
                $iv = $null
                try { $iv = [version]$vs } catch { $iv = $null }
                if ($iv -and ($iv -lt [version]$rule.Fixed)) {
                    $found += ($s.DisplayName + '   installed ' + $s.DisplayVersion + '   fixed in ' + $rule.Fixed + '   ' + $rule.Cve)
                    if ($rule.Sev -eq 'High') { $sv = 'High' }
                }
                break
            }
        }
    }
    $out = '(none found)'
    if ($found.Count -gt 0) { $out = $found -join "`n" }
    if (-not $sw) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read the software list.' '(no data)' }
    elseif ($found.Count -gt 0) { Add-Check $Num $Name 'BAD' ("$($found.Count) installed program(s) are older than the version that fixes known security flaws (WinRAR, 7-Zip, PuTTY).") $out $sv 'Update these programs to the latest version.' $out }
    else { Add-Check $Num $Name 'GOOD' 'WinRAR, 7-Zip and PuTTY (if installed) are new enough. (Only these few well-known programs are checked here; the outdated-apps check covers the rest.)' $out }
}

Invoke-Check 63 'Files that may hold passwords (names only)' {
    $rx = '(password|passwd|credential|login[ _-]?details)'
    $hits = @($userFiles | Where-Object { ($_.Extension -match '^\.(txt|doc|docx|xls|xlsx|csv|rtf|odt|ods)$') -and ($_.BaseName -match $rx) })
    $lines = @($hits | Select-Object -First 15 | ForEach-Object { $_.FullName })
    $out = '(none found)'
    if ($lines.Count -gt 0) { $out = $lines -join "`n" }
    if ($hits.Count -gt 0) { Add-Check $Num $Name 'BAD' ("$($hits.Count) file(s) in Downloads, Desktop or Documents have names that suggest stored passwords. (File contents were NOT read.)") $out 'Low' 'Keep passwords in a password manager, not in plain files. Delete these files after moving the passwords.' $out }
    else { Add-Check $Num $Name 'GOOD' 'No file name in Downloads, Desktop or Documents suggests stored passwords.' $out }
}

Invoke-Check 64 'Database and admin services open to the network' {
    $watch = @{ 1433 = 'SQL Server'; 3306 = 'MySQL / MariaDB'; 5432 = 'PostgreSQL'; 27017 = 'MongoDB'; 6379 = 'Redis'; 9200 = 'Elasticsearch'; 11211 = 'Memcached'; 1521 = 'Oracle'; 2375 = 'Docker API (no password)'; 5555 = 'Android debug (ADB)' }
    $conns = @(Get-NetTCPConnection -State Listen)
    if ($conns.Count -eq 0) { Add-Check $Num $Name 'NOT CHECKED' 'Could not read listening ports.' '(no data)'; return }
    $pn = @{}
    foreach ($pr in @(Get-Process)) { $pn[[int]$pr.Id] = [string]$pr.ProcessName }
    $rows = @()
    foreach ($c in $conns) {
        $port = [int]$c.LocalPort
        if ($watch.ContainsKey($port) -and ($c.LocalAddress -notin '127.0.0.1', '::1')) {
            $rows += [pscustomobject]@{ Port = $port; Service = $watch[$port]; Address = [string]$c.LocalAddress; Process = $pn[[int]$c.OwningProcess] }
        }
    }
    $rows = @($rows | Sort-Object Port -Unique)
    $lines = @($rows | ForEach-Object { 'Port ' + $_.Port + ' (' + $_.Service + ') is listening on ' + $_.Address + '  -  process: ' + $_.Process })
    $out = '(none found)'
    if ($lines.Count -gt 0) { $out = $lines -join "`n" }
    if ($rows.Count -gt 0) { Add-Check $Num $Name 'BAD' ('Database or admin service(s) accept connections from other computers: ' + (($rows | ForEach-Object { $_.Service + ' (' + $_.Port + ')' }) -join ', ') + '. Fine only if this PC is meant to be a server.') $out 'Medium' 'Bind the service to 127.0.0.1 if only this PC needs it, or block the port in the firewall for everyone except the computers that need it.' $out }
    else { Add-Check $Num $Name 'GOOD' 'No database or admin service is listening for other computers (ports checked: SQL Server, MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Memcached, Oracle, Docker, ADB).' $out }
}

Invoke-Check 65 'Persistence tricks (IFEO, AppInit, Winlogon, sign-in screen)' {
    $issues = @(); $lines = @()
    $rank = @{ 'Medium' = 1; 'High' = 2; 'Critical' = 3 }
    $top = 'Medium'
    $access = 'sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe', 'magnify.exe', 'displayswitch.exe', 'atbroker.exe'
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    foreach ($k in @(Get-ChildItem $ifeo)) {
        $dbg = [string](Get-ItemProperty -LiteralPath $k.PSPath).Debugger
        if ($dbg) {
            $n = [string]$k.PSChildName
            $lines += ($n + '  ->  Debugger = ' + $dbg)
            if ($access -contains $n.ToLower()) { $issues += ('Sign-in screen tool ' + $n + ' is replaced by: ' + $dbg + '.'); $top = 'Critical' }
            else { $issues += ('Program ' + $n + ' is redirected to: ' + $dbg + '.') }
        }
    }
    $cmdH = (Get-FileHash "$env:windir\System32\cmd.exe" -Algorithm SHA256).Hash
    $psH = (Get-FileHash "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -Algorithm SHA256).Hash
    foreach ($n in $access) {
        $f = "$env:windir\System32\$n"
        if (Test-Path -LiteralPath $f) {
            $h = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
            if ($h -and (($h -eq $cmdH) -or ($h -eq $psH))) { $lines += ($n + '  is a copy of cmd.exe or powershell.exe'); $issues += ('Sign-in screen tool ' + $n + ' is a copy of cmd.exe or PowerShell (sign-in screen backdoor).'); $top = 'Critical' }
        }
    }
    $win = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
    $ai = [string](RegVal $win 'AppInit_DLLs'); $li = RegVal $win 'LoadAppInit_DLLs'
    if ($ai.Trim() -and ($li -eq 1)) { $lines += ('AppInit_DLLs = ' + $ai); $issues += ('AppInit_DLLs is on and loads: ' + $ai + '.'); if ($rank[$top] -lt 2) { $top = 'High' } }
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $shell = [string](RegVal $wl 'Shell'); $ui = [string](RegVal $wl 'Userinit')
    if ($shell -and ($shell.Trim().ToLower() -ne 'explorer.exe')) { $lines += ('Winlogon Shell = ' + $shell); $issues += ('Windows shell is changed to: ' + $shell + '.'); if ($rank[$top] -lt 2) { $top = 'High' } }
    $uiOk = ($env:windir + '\system32\userinit.exe,').ToLower()
    if ($ui -and (($ui.Trim().Replace(' ', '').ToLower()) -ne $uiOk)) { $lines += ('Winlogon Userinit = ' + $ui); $issues += ('Winlogon Userinit is changed to: ' + $ui + '.'); if ($rank[$top] -lt 2) { $top = 'High' } }
    $out = '(none found)'
    if ($lines.Count -gt 0) { $out = $lines -join "`n" }
    if ($issues.Count -gt 0) { Add-Check $Num $Name 'BAD' ($issues -join ' ') $out $top 'Check these entries. If you do not recognise them, treat the PC as compromised: remove the entries, scan the PC and change passwords.' $out }
    else { Add-Check $Num $Name 'GOOD' 'No program redirection (IFEO), AppInit DLL, changed Winlogon shell/userinit, or replaced sign-in screen tool found.' $out }
}

# =============================================================================
# Build the HTML report (client report style: issues + proof only)
# =============================================================================
function Get-CssText { param([string]$s) return ($s -replace '["\\\r\n]', '') }

function Get-Evidence {
    param([string]$Text, [int]$Max = 16)
    if (-not $Text -or -not $Text.Trim()) { return '(no output)' }
    $lines = @(($Text -replace "`r", '') -split "`n")
    if ($lines.Count -le $Max) { return ($lines -join "`n").Trim() }
    return (($lines[0..($Max - 1)] -join "`n") + "`n... (" + ($lines.Count - $Max) + ' more lines not shown)')
}

$sorted   = @($script:results | Sort-Object Num)
$nGood    = @($sorted | Where-Object { $_.Status -eq 'GOOD' }).Count
$bads     = @($sorted | Where-Object { $_.Status -eq 'BAD' })
$nBad     = $bads.Count
$notRows  = @($sorted | Where-Object { $_.Status -eq 'NOT CHECKED' })
$nNot     = $notRows.Count
$notNames = @($notRows | ForEach-Object { $_.Name })
$sevOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }

# Every issue (Critical, High, Medium, Low) goes into the report
$listed = @($bads | Where-Object { $sevOrder.ContainsKey([string]$_.Sev) } | Sort-Object @{ Expression = { $sevOrder[$_.Sev] } }, Num)
$nCrit  = @($listed | Where-Object { $_.Sev -eq 'Critical' }).Count
$nHigh  = @($listed | Where-Object { $_.Sev -eq 'High' }).Count
$nMed   = @($listed | Where-Object { $_.Sev -eq 'Medium' }).Count
$nLow   = @($listed | Where-Object { $_.Sev -eq 'Low' }).Count
$nTotal = $listed.Count

# Issue ID prefix (e.g. MRT-01)
if ($DevicePrefix) {
    $prefix = ([string]$DevicePrefix).ToUpper()
} else {
    $pn = (($env:COMPUTERNAME -split '-')[-1] -replace '[^A-Za-z0-9]', '').ToUpper()
    if ($pn.Length -gt 4) { $pn = $pn.Substring(0, 3) }
    if (-not $pn) { $pn = 'EP' }
    $prefix = $pn
}
$items = @()
$k = 0
foreach ($r in $listed) {
    $k++
    $items += [pscustomobject]@{ Id = ('{0}-{1:00}' -f $prefix, $k); Poc = $k; R = $r }
}

# Device details
$osText = (($osAll.Caption -replace '^Microsoft\s+', '') + ' (build ' + $osAll.BuildNumber + ')')
$modelText = (([string]$cs.Manufacturer + ' ' + [string]$cs.Model)).Trim()
if ((-not [string]$cs.Model) -or ([string]$cs.Model -match 'O\.E\.M|System Product Name|Default string|To be filled|Not Applicable|System Version')) {
    $bb = Get-CimInstance Win32_BaseBoard
    $modelText = (([string]$bb.Manufacturer + ' ' + [string]$bb.Product)).Trim()
}
if (-not $modelText) { $modelText = '-' }
if (-not $ips) { $ips = '-' }
$dateLong = Get-Date -Format 'dd MMMM yyyy'

# ---------- Logo (embedded; a logo.png next to this script overrides it) ----------
$LogoEmbedded = ''  # no logo shipped by default; drop a logo.png next to this script to show one
$logoBytes = $null
if ($PSScriptRoot) {
    $lf = Join-Path $PSScriptRoot 'logo.png'
    if (Test-Path $lf) { try { $logoBytes = [System.IO.File]::ReadAllBytes($lf) } catch { $logoBytes = $null } }
}
if (-not $logoBytes) { try { $logoBytes = [Convert]::FromBase64String($LogoEmbedded) } catch { $logoBytes = $null } }
$logoHtml = ''
if ($logoBytes) { $logoHtml = '<img class="logo" src="data:image/png;base64,' + [Convert]::ToBase64String($logoBytes) + '" alt="logo">' }
$confWord = (([string]$Classification -split '-')[0]).Trim().ToUpper()
if (-not $confWord) { $confWord = 'CONFIDENTIAL' }

# ---------- Styles (model report format) ----------
$css = @'
*{-webkit-print-color-adjust:exact;print-color-adjust:exact;box-sizing:border-box}
body{font-family:Arial,Helvetica,sans-serif;font-size:11px;color:#1F2A37;margin:0;line-height:1.45}
h1{font-size:19px;color:#10294B;margin:0 0 8px;page-break-after:avoid}
h2{font-size:14px;color:#10294B;margin:16px 0 6px;page-break-after:avoid}
p{margin:0 0 8px}
.sec{margin-top:7mm}
.cover{page:cover;height:296mm;position:relative}
.ctop{background:#10294B;height:172mm;padding:34mm 16mm 0 16mm;color:#fff}
.ctag{font-size:9.5px;font-weight:bold;letter-spacing:1.5px;color:#9FB3CF;margin-bottom:12mm}
.ctitle{font-size:34px;font-weight:bold;line-height:1.2;margin-bottom:6mm}
.csub{font-size:13px;color:#CFDAEA}
.cstripe{height:2mm;background:#2F6DB5}
.cbody{padding:10mm 16mm 0 16mm}
.clogo{margin-bottom:6mm}
.logo{height:20mm}
.crow{display:flex;border-bottom:1px solid #D5DBE5;padding:9px 0}
.crow .l{width:42mm;font-size:10px;color:#6B7A90;letter-spacing:.5px}
.crow .v{font-size:12px;font-weight:bold;color:#10294B}
.cnote{font-size:9px;color:#6B7A90;margin-top:12mm}
.stats{display:flex;gap:10px;margin:10px 0 14px}
.stat{flex:1;background:#F3F5F8;border-top:4px solid #10294B;text-align:center;padding:12px 4px}
.stat b{display:block;font-size:28px;line-height:1.1;color:#10294B}
.stat span{font-size:8.5px;letter-spacing:1px;color:#5B6B80;font-weight:bold}
.stat.c{border-top-color:#8B0000}.stat.c b{color:#8B0000}
.stat.h{border-top-color:#C62828}.stat.h b{color:#C62828}
.stat.m{border-top-color:#E67E00}.stat.m b{color:#E67E00}
.stat.l{border-top-color:#2F6DB5}.stat.l b{color:#2F6DB5}
table.t{border-collapse:collapse;width:100%;margin:6px 0 10px;font-size:10px}
table.t th{background:#10294B;color:#fff;text-align:left;padding:7px 8px;font-size:10px}
table.t td{padding:6px 8px;border-bottom:1px solid #E1E6EE;vertical-align:top}
table.t tr:nth-child(even) td{background:#F6F8FB}
table.t tr{page-break-inside:avoid}
table.t td.id{font-weight:bold;white-space:nowrap}
table.t td.nm{font-weight:bold}
table.fd th:nth-child(1){width:9%}
table.fd th:nth-child(2){width:17%}
table.fd th:nth-child(3){width:11%}
table.fd th:nth-child(5){width:24%}
table.fd tr.sCRITICAL td:first-child{border-left:4px solid #8B0000}
table.fd tr.sHIGH td:first-child{border-left:4px solid #C62828}
table.fd tr.sMEDIUM td:first-child{border-left:4px solid #E67E00}
table.fd tr.sLOW td:first-child{border-left:4px solid #2F6DB5}
.pill{display:inline-block;color:#fff;font-weight:bold;font-size:8px;letter-spacing:.5px;padding:4px 0;width:58px;text-align:center;border-radius:2px}
.pill.CRITICAL{background:#8B0000}
.pill.HIGH{background:#C62828}
.pill.MEDIUM{background:#E67E00}
.pill.LOW{background:#2F6DB5}
.cnt{font-weight:bold}
.cnt.CRITICAL{color:#8B0000}
.cnt.HIGH{color:#C62828}
.cnt.MEDIUM{color:#E67E00}
.cnt.LOW{color:#2F6DB5}
table.info{width:100%;border-collapse:collapse;background:#F3F5F8;border-left:4px solid #10294B;margin:8px 0 10px}
table.info td{padding:6px 10px;font-size:10.5px;border:0}
table.info td.l{font-weight:bold;width:17%}
.note{font-size:9px;color:#5B6B80;margin:4px 0 8px}
.key{display:flex;align-items:center;margin:5px 0}
.key .pill{margin-right:10px}
.ref{color:#2F6DB5;font-weight:bold;white-space:nowrap}
.pocs{display:flex;flex-wrap:wrap;gap:8px}
.poc{width:calc(50% - 4px);page-break-inside:avoid;break-inside:avoid}
.poc.wide{width:100%}
.ph{background:#2F6DB5;color:#fff;font-weight:bold;font-size:9px;padding:5px 8px}
.poc pre{background:#10294B;color:#DCE6F2;margin:0;padding:8px;font-family:Consolas,"Courier New",monospace;font-size:8.5px;white-space:pre-wrap;word-break:break-word;line-height:1.4}
@page cover{margin:0}
'@

$hdrBg = 'linear-gradient(to bottom,#10294B 0,#10294B 11mm,transparent 11mm)'
$hdrL = Get-CssText ($PreparedBy + '  |  Endpoint Security Assessment Report')
$ftrL = Get-CssText ('Prepared by ' + $PreparedBy)
$pageCss = '@page{size:A4;margin:20mm 15mm 18mm 15mm;' +
    '@top-left-corner{content:"";background:' + $hdrBg + '}' +
    '@top-left{content:"' + $hdrL + '";background:' + $hdrBg + ';color:#fff;font-size:9px;font-weight:bold;vertical-align:top;padding-top:3.6mm;font-family:Arial,sans-serif}' +
    '@top-center{content:"";background:' + $hdrBg + '}' +
    '@top-right{content:"' + $confWord + '";background:' + $hdrBg + ';color:#C9D6EA;font-size:9px;text-align:right;vertical-align:top;padding-top:3.6mm;font-family:Arial,sans-serif}' +
    '@top-right-corner{content:"";background:' + $hdrBg + '}' +
    '@bottom-left{content:"' + $ftrL + '";font-size:9px;color:#5B7BA6;border-top:0.5pt solid #C8D0DC;padding-top:4px;width:50%;font-family:Arial,sans-serif}' +
    '@bottom-right{content:"Page " counter(page);font-size:9px;color:#5B7BA6;text-align:right;border-top:0.5pt solid #C8D0DC;padding-top:4px;width:50%;font-family:Arial,sans-serif}}' +
    '@page cover{@top-left{content:none}}'

# ---------- Page text ----------
$preparedE = Enc $PreparedBy
$clientVal = $ips
if ($SystemLabel) { $clientVal = $SystemLabel + ' (' + $ips + ')' }
elseif ($ClientName) { $clientVal = $ClientName + ' (' + $ips + ')' }
$devName = $env:COMPUTERNAME
if ($SystemLabel) { $devName = $env:COMPUTERNAME + ' (' + $SystemLabel + ')' }

$execHtml = Enc ('One Windows endpoint (' + $devName + ', ' + $ips + ') was assessed on ' + $dateLong + '.')
if ($nTotal -eq 0) {
    $execHtml += ' No issues were found.'
} else {
    $pp = @()
    if ($nCrit -gt 0) { $pp += ('<b>' + $nCrit + ' Critical</b>') }
    if ($nHigh -gt 0) { $pp += ('<b>' + $nHigh + ' High</b>') }
    if ($nMed -gt 0)  { $pp += ('<b>' + $nMed + ' Medium</b>') }
    if ($nLow -gt 0)  { $pp += ('<b>' + $nLow + ' Low</b>') }
    $execHtml += ' A total of <b>' + $nTotal + ' issues</b> were found: ' + ($pp -join ', ') + '. Fix Critical and High issues first.'
    $topNames = @($items | Where-Object { $_.R.Sev -eq 'Critical' -or $_.R.Sev -eq 'High' } | ForEach-Object { $_.R.Name })
    if ($topNames.Count -gt 0) { $execHtml += ' The Critical and High issues are: ' + (Enc ($topNames -join '; ')) + '.' }
}

$noteParts = @('Severity is rated by the impact of the issue on that endpoint. Every issue is shown with its proof (PoC).')
if ($nNot -gt 0) { $noteParts += ($nNot.ToString() + ' check(s) could not be completed (listed below).') }
$noteText = 'Note: ' + ($noteParts -join ' ')
$issuesHtml = $nTotal.ToString() + ' ('
$ip2 = @()
if ($nCrit -gt 0) { $ip2 += ('<b class="cnt CRITICAL">' + $nCrit + ' Critical</b>') }
if ($nHigh -gt 0) { $ip2 += ('<b class="cnt HIGH">' + $nHigh + ' High</b>') }
if ($nMed -gt 0)  { $ip2 += ('<b class="cnt MEDIUM">' + $nMed + ' Medium</b>') }
if ($nLow -gt 0)  { $ip2 += ('<b class="cnt LOW">' + $nLow + ' Low</b>') }
if ($ip2.Count -eq 0) { $issuesHtml = '0' } else { $issuesHtml = '<b>' + $nTotal + '</b> (' + ($ip2 -join ', ') + ')' }

# ---------- Build the HTML ----------
$sb = New-Object System.Text.StringBuilder
function Add-Html { param([string]$s) [void]$sb.AppendLine($s) }

Add-Html ('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Endpoint Security Assessment Report</title><style>' + $css + $pageCss + '</style></head><body>')

# Cover page
Add-Html '<div class="cover">'
Add-Html '<div class="ctop"><div class="ctag">VAPT &nbsp;|&nbsp; ENDPOINT AUDIT</div><div class="ctitle">Endpoint Security<br>Assessment Report</div><div class="csub">Windows endpoint vulnerability assessment &ndash; 1 device</div></div>'
Add-Html '<div class="cstripe"></div>'
Add-Html '<div class="cbody">'
if ($ShowLogo -and $logoHtml) { Add-Html ('<div class="clogo">' + $logoHtml + '</div>') }
Add-Html ('<div class="crow"><div class="l">CLIENT</div><div class="v">' + (Enc $clientVal) + '</div></div>')
Add-Html ('<div class="crow"><div class="l">REPORT DATE</div><div class="v">' + $dateLong + '</div></div>')
Add-Html ('<div class="crow"><div class="l">ASSESSMENT DATE</div><div class="v">' + $dateLong + '</div></div>')
Add-Html ('<div class="crow"><div class="l">PREPARED BY</div><div class="v">' + $preparedE + '</div></div>')
Add-Html ('<div class="crow"><div class="l">CLASSIFICATION</div><div class="v">' + (Enc $Classification) + '</div></div>')
Add-Html '<div class="cnote">This report is confidential and intended only for the recipient named above.</div>'
Add-Html '</div></div>'

# 1. Executive summary
Add-Html '<div class="sec"><h1>1. Executive Summary</h1>'
Add-Html ('<p>' + $execHtml + '</p>')
Add-Html ('<div class="stats"><div class="stat"><b>' + $nTotal + '</b><span>TOTAL ISSUES</span></div><div class="stat c"><b>' + $nCrit + '</b><span>CRITICAL</span></div><div class="stat h"><b>' + $nHigh + '</b><span>HIGH</span></div><div class="stat m"><b>' + $nMed + '</b><span>MEDIUM</span></div><div class="stat l"><b>' + $nLow + '</b><span>LOW</span></div></div>')
Add-Html '</div>'

# 2. Scope and results
Add-Html '<div class="sec"><h1>2. Scope and Results by Endpoint</h1>'
Add-Html '<table class="t"><tr><th>Endpoint</th><th>IP Address</th><th>Operating System</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr>'
Add-Html ('<tr><td class="nm">' + (Enc $devName) + '</td><td>' + (Enc $ips) + '</td><td>' + (Enc $osText) + '</td><td class="cnt CRITICAL">' + $nCrit + '</td><td class="cnt HIGH">' + $nHigh + '</td><td class="cnt MEDIUM">' + $nMed + '</td><td class="cnt LOW">' + $nLow + '</td><td class="nm">' + $nTotal + '</td></tr>')
Add-Html '</table>'
Add-Html ('<div class="note"><b>Note:</b> ' + (Enc ($noteText -replace '^Note: ', '')) + '</div>')
if ($nNot -gt 0) {
    Add-Html '<h2>Checks not completed</h2>'
    Add-Html '<table class="t"><tr><th>Check</th><th>Reason</th></tr>'
    foreach ($r in $notRows) {
        Add-Html ('<tr><td class="nm">' + (Enc $r.Name) + '</td><td>' + (Enc $r.Finding) + '</td></tr>')
    }
    Add-Html '</table>'
    Add-Html '<div class="note">These checks are NOT counted as issues. A re-check with full administrator rights is advised.</div>'
}
Add-Html '<h2>Severity key</h2>'
Add-Html '<div class="key"><span class="pill CRITICAL">CRITICAL</span> Active attack signs, or a weakness that gives full control at once. Fix immediately.</div>'
Add-Html '<div class="key"><span class="pill HIGH">HIGH</span> Can lead to data theft, system takeover or loss. Fix first.</div>'
Add-Html '<div class="key"><span class="pill MEDIUM">MEDIUM</span> Weakens security or helps an attacker. Fix after High issues.</div>'
Add-Html '<div class="key"><span class="pill LOW">LOW</span> Small risk or best-practice gap. Fix when convenient.</div>'
Add-Html '</div>'

# 3. Summary of all findings
Add-Html '<div class="sec"><h1>3. Summary of All Findings</h1>'
if ($nTotal -eq 0) {
    Add-Html '<p>No issues were found on this endpoint.</p>'
} else {
    Add-Html '<table class="t"><tr><th>No.</th><th>Device</th><th>Issue</th><th>Severity</th></tr>'
    foreach ($it in $items) {
        $sv = $it.R.Sev.ToUpper()
        Add-Html ('<tr><td class="id">' + $it.Id + '</td><td>' + (Enc $devName) + '</td><td>' + (Enc $it.R.Name) + '</td><td><span class="pill ' + $sv + '">' + $sv + '</span></td></tr>')
    }
    Add-Html '</table>'
}
Add-Html '</div>'

# Endpoint page
Add-Html ('<div class="sec"><h1>Endpoint: ' + (Enc $devName) + '</h1>')
Add-Html ('<table class="info"><tr><td class="l">IP Address</td><td>' + (Enc $ips) + '</td><td class="l">Operating System</td><td>' + (Enc $osText) + '</td></tr><tr><td class="l">Model</td><td>' + (Enc $modelText) + '</td><td class="l">Issues Found</td><td>' + $issuesHtml + '</td></tr></table>')
if ($nTotal -gt 0) {
    Add-Html '<table class="t fd"><tr><th>No.</th><th>Finding</th><th>Severity</th><th>Description</th><th>Recommendation</th></tr>'
    foreach ($it in $items) {
        $r = $it.R
        $sv = $r.Sev.ToUpper()
        $desc = (Enc $r.Finding) + ' <span class="ref">[PoC-' + $it.Poc + ']</span>'
        Add-Html ('<tr class="s' + $sv + '"><td class="id">' + $it.Id + '</td><td class="nm">' + (Enc $r.Name) + '</td><td><span class="pill ' + $sv + '">' + $sv + '</span></td><td>' + $desc + '</td><td>' + (Enc $r.Fix) + '</td></tr>')
    }
    Add-Html '</table>'
}
Add-Html ('<div class="note"><b>Note:</b> ' + (Enc ($noteText -replace '^Note: ', '')) + '</div>')

# Proof of concept
if ($nTotal -gt 0) {
    Add-Html '<h2>Proof of Concept (key evidence from the scan)</h2>'
    Add-Html '<div class="pocs">'
    foreach ($it in $items) {
        $pt = [string]$it.R.Poc
        if (-not $pt.Trim()) { $pt = [string]$it.R.Output }
        $pt = $pt -replace '=\s+\(', '= not set (' -replace '=\s+seconds', '= not set (seconds)' -replace '=\s+,', '= not set,'
        $pt = [regex]::Replace($pt, '(?m)^(Excluded [a-z]+):\s*$', '$1: (none)')
        $ev = Get-Evidence $pt 18
        $mx = 0
        foreach ($ln in @($ev -split "`n")) { if ($ln.Length -gt $mx) { $mx = $ln.Length } }
        $wide = ''
        if ($mx -gt 44) { $wide = ' wide' }
        Add-Html ('<div class="poc' + $wide + '"><div class="ph">PoC-' + $it.Poc + ' &nbsp;|&nbsp; ' + $it.Id + ' &nbsp;|&nbsp; ' + (Enc $it.R.Name) + '</div><pre>' + (Enc $ev) + '</pre></div>')
    }
    Add-Html '</div>'
}
Add-Html '</div></body></html>'

[System.IO.File]::WriteAllText($html, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))

# =============================================================================
# Make the PDF (Edge or Chrome, headless)
# =============================================================================
$browsers = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe",
    "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
)
$browser = $browsers | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($browser) {
    Write-Host 'Making the PDF ...'
    $tmp = Join-Path $env:TEMP ('pdfprofile_' + [guid]::NewGuid().ToString('N'))
    $browserArgs = @(
        '--headless', '--disable-gpu', '--no-pdf-header-footer',
        ('--user-data-dir="{0}"' -f $tmp),
        ('--print-to-pdf="{0}"' -f $pdf),
        ('"{0}"' -f ([uri]$html).AbsoluteUri)
    )
    Start-Process -FilePath $browser -ArgumentList $browserArgs -Wait -WindowStyle Hidden
    for ($i = 0; $i -lt 30 -and -not (Test-Path $pdf); $i++) { Start-Sleep -Seconds 1 }
    Start-Sleep -Seconds 1
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host ("RESULT: GOOD {0} | BAD {1} | NOT CHECKED {2}" -f $nGood, $nBad, $nNot) -ForegroundColor Cyan
if (Test-Path $pdf) {
    Write-Host "DONE. PDF saved here: $pdf" -ForegroundColor Green
    Start-Process explorer.exe -ArgumentList ('/select,"{0}"' -f $pdf)
} else {
    Write-Host 'PDF could not be made automatically.' -ForegroundColor Yellow
    Write-Host "Open this file in a browser, press Ctrl+P, choose Save as PDF: $html" -ForegroundColor Yellow
    Start-Process explorer.exe -ArgumentList ('/select,"{0}"' -f $html)
}
Write-Host ''
Read-Host 'Press Enter to close'
