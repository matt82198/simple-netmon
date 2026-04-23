# netmon-ui.ps1 — Live connection monitor, auto-refreshing, IOC-aware
# Run: powershell -ExecutionPolicy Bypass -File netmon-ui.ps1

$port   = 8181
$iocs   = @('20.49.91.128','34.237.6.16','20.190.157.1','34.98.64.218')
$benign = @('160.79.104.10','127.0.0.1','::1','0.0.0.0')

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://localhost:$port/")
$listener.Start()
Write-Host "NetMon running → http://localhost:$port" -ForegroundColor Green
Start-Process "http://localhost:$port"

function Get-Snapshot {
    $procs = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procs["$($_.Id)"] = $_.ProcessName }

    $rows = netstat -ano 2>$null |
        Select-String '^\s+(TCP|UDP)' |
        ForEach-Object {
            $p = $_.ToString().Trim() -split '\s+'
            $proto   = $p[0]
            $local   = $p[1]
            $foreign = if ($p.Count -gt 2) { $p[2] } else { '-' }
            $state   = if ($proto -eq 'TCP' -and $p.Count -gt 3) { $p[3] } else { '-' }
            $pid_    = $p[-1]
            $proc    = if ($procs.ContainsKey($pid_)) { $procs[$pid_] } else { "?" }
            $fip     = ($foreign -split ':')[0] -replace '^\[','' -replace '\]$',''

            $cls = 'n'
            if ($iocs  -contains $fip) { $cls = 'ioc' }
            elseif ($state -eq 'ESTABLISHED') { $cls = 'est' }

            "<tr class='$cls'><td>$proto</td><td>$local</td><td>$foreign</td><td>$state</td><td>$pid_</td><td>$proc</td></tr>"
        }

    $iocHits = ($rows | Where-Object { $_ -match "class='ioc'" }).Count
    $banner  = if ($iocHits -gt 0) {
        "<div class='alert'>⚠ $iocHits IOC CONNECTION(S) ACTIVE</div>"
    } else {
        "<div class='ok'>No IOC IPs detected</div>"
    }

    return $banner, ($rows -join "`n"), $rows.Count
}

while ($listener.IsListening) {
    $ctx = $listener.GetContext()
    $b, $tbl, $cnt = Get-Snapshot
    $ts  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $html = @"
<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>NetMon $ts</title>
<meta http-equiv='refresh' content='5'>
<style>
*{box-sizing:border-box}
body{background:#0d0d0d;color:#ccc;font-family:'Courier New',monospace;margin:0;padding:16px}
h2{color:#ff6b6b;margin:0 0 8px}
.meta{color:#555;font-size:.8em;margin-bottom:12px}
.alert{background:#5a0000;color:#ff4444;border:1px solid #ff0000;padding:10px;margin-bottom:12px;font-weight:bold}
.ok{background:#003300;color:#00ff88;border:1px solid #00aa44;padding:8px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:.85em}
th{background:#1a1a3e;color:#7eb8f7;padding:7px 10px;text-align:left;position:sticky;top:0}
td{padding:5px 10px;border-bottom:1px solid #1a1a1a;white-space:nowrap}
tr.ioc{background:#3a0000;color:#ff4444;font-weight:bold}
tr.est{background:#001a00}
tr.n{}
tr:hover td{background:#1f1f1f}
.ioc td{color:#ff4444}
</style></head><body>
<h2>NetMon Live</h2>
<div class='meta'>$ts &nbsp;|&nbsp; $cnt connections &nbsp;|&nbsp; auto-refresh 5s &nbsp;|&nbsp; IOC IPs: $($iocs -join ' · ')</div>
$b
<table><tr><th>Proto</th><th>Local</th><th>Foreign</th><th>State</th><th>PID</th><th>Process</th></tr>
$tbl
</table></body></html>
"@

    $buf = [System.Text.Encoding]::UTF8.GetBytes($html)
    $ctx.Response.ContentType   = 'text/html; charset=utf-8'
    $ctx.Response.ContentLength64 = $buf.Length
    $ctx.Response.OutputStream.Write($buf, 0, $buf.Length)
    $ctx.Response.OutputStream.Close()
}
