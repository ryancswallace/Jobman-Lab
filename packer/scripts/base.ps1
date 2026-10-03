$ErrorActionPreference = 'Stop'

$logDirectory = 'C:\Windows\Temp\jobman-lab'
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
Start-Transcript -Path (Join-Path $logDirectory 'parallels-tools.log') -Append

try {
    powercfg.exe /hibernate off

    $toolsAgent = Get-PSDrive -PSProvider FileSystem |
        ForEach-Object { Join-Path $_.Root 'PTAgent.exe' } |
        Where-Object { Test-Path -LiteralPath $_ } |
        Select-Object -First 1
    if (-not $toolsAgent) {
        throw 'Parallels Tools installer is not available on an attached volume'
    }

    $toolsInstall = Start-Process -FilePath $toolsAgent -ArgumentList '/install_silent' -Wait -PassThru
    if ($toolsInstall.ExitCode -notin @(0, 3010)) {
        throw "Parallels Tools installation failed with exit code $($toolsInstall.ExitCode)"
    }
}
finally {
    Stop-Transcript
}
