# Show user folder
function ShowUserFolderOnExplorer {
    Write-Output "Showing User folder on Explorer namespace..."
    if (!(Test-Path "HKCU:\SOFTWARE\Classes\CLSID\{59031a47-3f72-44a7-89c5-5595fe6b30ee}")) {
        New-Item -Path "HKCU:\SOFTWARE\Classes\CLSID\{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Name "System.IsPinnedToNameSpaceTree" -Type DWORD -Value 1
}

# Hide user folder
function HideUserFolderOnExplorer {
    Write-Output "Hiding User folder on Explorer namespace..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Name "System.IsPinnedToNameSpaceTree" -ErrorAction SilentlyContinue
}

# Enable MarkC mousefix
function EnableMarkCMouseFix {
    Write-Output "Enabling MarkC mousefix for 100 dpi..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Type String -Value "10"
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseXCurve" -Type Binary -Value ([byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xCC, 0x0C,`
                                                                                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x99, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,`
                                                                                                    0x40, 0x66, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00))
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseYCurve" -Type Binary -Value ([byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38,`
                                                                                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00,`
                                                                                                    0x00, 0x00, 0xA8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00))
}

# Disable MarkC mousefix
function DisableMarkCMouseFix {
    Write-Output "Disabling MarkC mousefix..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseXCurve" -Type Binary -Value ([byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x6e, 0x00,`
                                                                                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,`
                                                                                                    0x29, 0xdc, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00))
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseYCurve" -Type Binary -Value ([byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x11, 0x01,`
                                                                                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,`
                                                                                                    0x00, 0xfc, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xbb, 0x01, 0x00, 0x00, 0x00, 0x00))
}

# Add telemtry ips
function AddTelemetryIPsToFirewall {
    # Credits: https://github.com/W4RH4WK/Debloat-Windows-10/
    $Ips = @(
        "134.170.30.202"
        "137.116.81.24"
        "157.56.106.189"
        "184.86.53.99"
        "2.22.61.43"
        "2.22.61.66"
        "204.79.197.200"
        "23.218.212.69"
        "65.39.117.230"
        "65.52.108.33"  # Causes problems with Microsoft Store
        "65.55.108.23"
        "64.4.54.254"
    )
    Write-Output "Adding telemetry IPs to Windows Firewall..."
    New-NetFirewallRule -DisplayName "Block Telemetry IPs" -Direction Outbound -Action Block -RemoteAddress ([string[]]$Ips) | Out-Null
}

# Remove telemetry ips
function RemoveTelemetryIPsFromFirewall {
    Write-Output "Removing telemtry IPs from Windows Firewall..."
    Remove-NetFirewallRule -DisplayName "Block Telemetry IPs" -ErrorAction SilentlyContinue
}

# Add telemtry domains
function AddTelemetryToHosts {
    # Credits: https://github.com/W4RH4WK/Debloat-Windows-10/
    # If the first or last domain changes update the variables in RemoveTelemetryFromHosts also
    $Domains = @(
        "184-86-53-99.deploy.static.akamaitechnologies.com"
        "a-0001.a-msedge.net"
        "a-0002.a-msedge.net"
        "a-0003.a-msedge.net"
        "a-0004.a-msedge.net"
        "a-0005.a-msedge.net"
        "a-0006.a-msedge.net"
        "a-0007.a-msedge.net"
        "a-0008.a-msedge.net"
        "a-0009.a-msedge.net"
        "a1621.g.akamai.net"
        "a1856.g2.akamai.net"
        "a1961.g.akamai.net"
        #"a248.e.akamai.net"            # makes iTunes download button disappear (#43)
        "a978.i6g1.akamai.net"
        "a.ads1.msn.com"
        "a.ads2.msads.net"
        "a.ads2.msn.com"
        "ac3.msn.com"
        "ad.doubleclick.net"
        "adnexus.net"
        "adnxs.com"
        "ads1.msads.net"
        "ads1.msn.com"
        "ads.msn.com"
        "aidps.atdmt.com"
        "aka-cdn-ns.adtech.de"
        "a-msedge.net"
        "any.edge.bing.com"
        "a.rad.msn.com"
        "az361816.vo.msecnd.net"
        "az512334.vo.msecnd.net"
        "b.ads1.msn.com"
        "b.ads2.msads.net"
        "bingads.microsoft.com"
        "b.rad.msn.com"
        "bs.serving-sys.com"
        "c.atdmt.com"
        "cdn.atdmt.com"
        "cds26.ams9.msecn.net"
        "choice.microsoft.com"
        "choice.microsoft.com.nsatc.net"
        "compatexchange.cloudapp.net"
        "corpext.msitadfs.glbdns2.microsoft.com"
        "corp.sts.microsoft.com"
        "cs1.wpc.v0cdn.net"
        "db3aqu.atdmt.com"
        "df.telemetry.microsoft.com"
        "diagnostics.support.microsoft.com"
        "e2835.dspb.akamaiedge.net"
        "e7341.g.akamaiedge.net"
        "e7502.ce.akamaiedge.net"
        "e8218.ce.akamaiedge.net"
        "ec.atdmt.com"
        "fe2.update.microsoft.com.akadns.net"
        "feedback.microsoft-hohm.com"
        "feedback.search.microsoft.com"
        "feedback.windows.com"
        "flex.msn.com"
        "g.msn.com"
        "h1.msn.com"
        "h2.msn.com"
        "hostedocsp.globalsign.com"
        "i1.services.social.microsoft.com"
        "i1.services.social.microsoft.com.nsatc.net"
        #"ipv6.msftncsi.com"                    # Issues may arise where Windows 10 thinks it doesn't have internet
        #"ipv6.msftncsi.com.edgesuite.net"      # Issues may arise where Windows 10 thinks it doesn't have internet
        "lb1.www.ms.akadns.net"
        "live.rads.msn.com"
        "m.adnxs.com"
        "msedge.net"
        #"msftncsi.com"
        "msnbot-65-55-108-23.search.msn.com"
        "msntest.serving-sys.com"
        "oca.telemetry.microsoft.com"
        "oca.telemetry.microsoft.com.nsatc.net"
        "onesettings-db5.metron.live.nsatc.net"
        "pre.footprintpredict.com"
        "preview.msn.com"
        "rad.live.com"
        "rad.msn.com"
        "redir.metaservices.microsoft.com"
        "reports.wes.df.telemetry.microsoft.com"
        "schemas.microsoft.akadns.net"
        "secure.adnxs.com"
        "secure.flashtalking.com"
        "services.wes.df.telemetry.microsoft.com"
        "settings-sandbox.data.microsoft.com"
        #"settings-win.data.microsoft.com"       # may cause issues with Windows Updates
        "sls.update.microsoft.com.akadns.net"
        #"sls.update.microsoft.com.nsatc.net"    # may cause issues with Windows Updates
        "sqm.df.telemetry.microsoft.com"
        "sqm.telemetry.microsoft.com"
        "sqm.telemetry.microsoft.com.nsatc.net"
        "ssw.live.com"
        "static.2mdn.net"
        "statsfe1.ws.microsoft.com"
        "statsfe2.update.microsoft.com.akadns.net"
        "statsfe2.ws.microsoft.com"
        "survey.watson.microsoft.com"
        "telecommand.telemetry.microsoft.com"
        "telecommand.telemetry.microsoft.com.nsatc.net"
        "telemetry.appex.bing.net"
        "telemetry.microsoft.com"
        "telemetry.urs.microsoft.com"
        "vortex-bn2.metron.live.com.nsatc.net"
        "vortex-cy2.metron.live.com.nsatc.net"
        "vortex.data.microsoft.com"
        "vortex-sandbox.data.microsoft.com"
        "vortex-win.data.microsoft.com"
        "cy2.vortex.data.microsoft.com.akadns.net"
        "watson.live.com"
        "watson.microsoft.com"
        "watson.ppe.telemetry.microsoft.com"
        "watson.telemetry.microsoft.com"
        "watson.telemetry.microsoft.com.nsatc.net"
        "wes.df.telemetry.microsoft.com"
        "win10.ipv6.microsoft.com"
        "www.bingads.microsoft.com"
        "www.go.microsoft.akadns.net"
        #"www.msftncsi.com"                         # Issues may arise where Windows 10 thinks it doesn't have internet
        "client.wns.windows.com"
        #"wdcp.microsoft.com"                       # may cause issues with Windows Defender Cloud-based protection
        #"dns.msftncsi.com"                         # This causes Windows to think it doesn't have internet
        #"storeedgefd.dsx.mp.microsoft.com"         # breaks Windows Store
        "wdcpalt.microsoft.com"
        "settings-ssl.xboxlive.com"
        "settings-ssl.xboxlive.com-c.edgekey.net"
        "settings-ssl.xboxlive.com-c.edgekey.net.globalredir.akadns.net"
        "e87.dspb.akamaidege.net"
        "insiderservice.microsoft.com"
        "insiderservice.trafficmanager.net"
        "e3843.g.akamaiedge.net"
        "flightingserviceweurope.cloudapp.net"
        #"sls.update.microsoft.com"                 # may cause issues with Windows Updates
        "static.ads-twitter.com"                    # may cause issues with Twitter login
        "www-google-analytics.l.google.com"
        "p.static.ads-twitter.com"                  # may cause issues with Twitter login
        "hubspot.net.edge.net"
        "e9483.a.akamaiedge.net"

        #"www.google-analytics.com"
        #"padgead2.googlesyndication.com"
        #"mirror1.malwaredomains.com"
        #"mirror.cedia.org.ec"
        "stats.g.doubleclick.net"
        "stats.l.doubleclick.net"
        "adservice.google.de"
        "adservice.google.com"
        "googleads.g.doubleclick.net"
        "pagead46.l.doubleclick.net"
        "hubspot.net.edgekey.net"
        "insiderppe.cloudapp.net"                   # Feedback-Hub
        "livetileedge.dsx.mp.microsoft.com"

        # extra
        "fe2.update.microsoft.com.akadns.net"
        "s0.2mdn.net"
        "statsfe2.update.microsoft.com.akadns.net"
        "survey.watson.microsoft.com"
        "view.atdmt.com"
        "watson.microsoft.com"
        "watson.ppe.telemetry.microsoft.com"
        "watson.telemetry.microsoft.com"
        "watson.telemetry.microsoft.com.nsatc.net"
        "wes.df.telemetry.microsoft.com"
        "m.hotmail.com"

        # can cause issues with Skype (#79) or other services (#171)
        "apps.skype.com"
        "c.msn.com"
        # "login.live.com"                  # prevents login to outlook and other live apps
        "pricelist.skype.com"
        "s.gateway.messenger.live.com"
        "ui.skype.com"
    )

    Write-Output "Adding telemetry domains to hosts file..."
    for ($i = 0; $i -lt $Domains.Count; $i++) {
        if ($i -eq 0) {
            Write-Output "" | Out-File "$env:SystemRoot\System32\drivers\etc\hosts" -Encoding utf8 -Append
        }
        if (!(Select-String -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Encoding utf8 -Pattern $($Domains[$i]))) {
            Write-Output "0.0.0.0 $($Domains[$i])" | Out-File "$env:SystemRoot\System32\drivers\etc\hosts" -Encoding utf8 -Append
        }
    }
}

# Remove telemetry domains
function RemoveTelemetryFromHosts {
    Write-Output "Removing telemetry domains from hosts file..."
    $Hosts = Get-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Encoding utf8
    $Begin = $Hosts.IndexOf("0.0.0.0 184-86-53-99.deploy.static.akamaitechnologies.com")
    $End = $Hosts.IndexOf("0.0.0.0 ui.skype.com")
    $Hosts[0..$($Begin-1)] + $Hosts[$($End+1)..$Hosts.Count] | Out-File "$env:SystemRoot\System32\drivers\etc\hosts" -Encoding utf8
}

# Enable low ram
function EnableLowRam {
    # Credits: https://github.com/W4RH4WK/Debloat-Windows-10/
    Write-Output "Enabling low ram usage..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 4000000
}

# Disable low ram
function DisableLowRam {
    Write-Output "Disabling low ram usage..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 380000
}

# Enable SSD tweaks
function EnableSSDTweaks {
    Write-Output "Enabling SSD life improvements..."
    fsutil behavior set EncryptPagingFile 0 | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" -Name "TimeStampInterval" -Type DWord -Value 0
}

# Disable SSD tweaks
function DisableSSDTweaks {
    Write-Output "Disabling SSD life improvements..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" -Name "TimeStampInterval" -Type DWord -Value 1
}