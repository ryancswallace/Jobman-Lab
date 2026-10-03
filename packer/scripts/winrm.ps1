$ErrorActionPreference = 'Stop'

$logDirectory = 'C:\Windows\Temp\jobman-lab'
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
Start-Transcript -Path (Join-Path $logDirectory 'winrm.log') -Append

$networkProfile = $null
$restorePublicProfile = $false
try {
    $activeProfiles = @(
        Get-NetConnectionProfile |
            Where-Object { $_.IPv4Connectivity -ne 'Disconnected' }
    )
    if ($activeProfiles.Count -ne 1) {
        throw "expected one active IPv4 network profile during image build, found $($activeProfiles.Count)"
    }
    $networkProfile = $activeProfiles[0]
    if ($networkProfile.NetworkCategory -eq 'Public') {
        Set-NetConnectionProfile -InterfaceIndex $networkProfile.InterfaceIndex -NetworkCategory Private
        $restorePublicProfile = $true
    }

    Set-Service -Name WinRM -StartupType Automatic
    Enable-PSRemoting -SkipNetworkProfileCheck -Force

    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force | Out-Null

    $certificate = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation 'Cert:\LocalMachine\My'
    $listenerValues = '@{Hostname="' + $env:COMPUTERNAME + '";CertificateThumbprint="' + $certificate.Thumbprint + '"}'
    & winrm create 'winrm/config/Listener?Address=*+Transport=HTTPS' $listenerValues
    if ($LASTEXITCODE -ne 0) {
        throw "TLS WinRM listener creation failed with exit code $LASTEXITCODE"
    }

    & winrm set winrm/config/service/auth '@{Basic="true"}'
    if ($LASTEXITCODE -ne 0) {
        throw "WinRM Basic authentication configuration failed with exit code $LASTEXITCODE"
    }
    & winrm set winrm/config/service '@{AllowUnencrypted="false"}'
    if ($LASTEXITCODE -ne 0) {
        throw "WinRM encryption policy configuration failed with exit code $LASTEXITCODE"
    }

    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    New-NetFirewallRule -DisplayName 'Jobman Lab WinRM TLS' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5986 -Profile Any -ErrorAction SilentlyContinue | Out-Null

    if (-not (Get-NetTCPConnection -LocalPort 5986 -State Listen -ErrorAction SilentlyContinue)) {
        throw 'TLS WinRM listener is not active on port 5986'
    }
}
finally {
    try {
        if ($restorePublicProfile -and $null -ne $networkProfile) {
            Set-NetConnectionProfile -InterfaceIndex $networkProfile.InterfaceIndex -NetworkCategory Public
        }
    }
    finally {
        Stop-Transcript
    }
}
