Set-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)

# Remove existing src directory if it exists, to ensure a clean clone
if (Test-Path src) {
    Remove-Item -Recurse -Force src
}

git clone https://github.com/XTLS/Xray-core -b 'v25.6.8' src
if ( -Not $? ) {
    Write-Error "Failed to clone Xray-core repository."
    exit $lastExitCode
}
Set-Location src

$Env:CGO_ENABLED='0'
$Env:GOROOT_FINAL='/usr' # This might not be necessary for Xray-core builds, but keeping for consistency for now

$Env:GOOS='windows'
$Env:GOARCH='amd64'

Write-Host "Building xray.exe..."
go build -a -trimpath -asmflags '-s -w' -ldflags '-s -w -buildid=' -o '..\..\release\xray.exe' '.\main'
if ( -Not $? ) {
    Write-Error "Failed to build xray.exe."
    exit $lastExitCode
}

# v2ctl.exe is no longer built from this path in Xray-core.
# Write-Host "Building v2ctl.exe (now xrayctl.exe potentially, or removed)..."
# go build -a -trimpath -asmflags '-s -w' -ldflags '-s -w -buildid=' -tags confonly -o '..\..\release\xrayctl.exe' '.\infra\control\main' # Path needs verification if utility is still built
# if ( -Not $? ) {
#     Write-Warning "Failed to build xrayctl.exe. This might be normal if the utility path changed or was removed."
#     # Do not exit, as the main xray.exe is more critical.
# }

Write-Host "Building wxray.exe..."
go build -a -trimpath -asmflags '-s -w' -ldflags '-s -w -buildid= -H windowsgui' -o '..\..\release\wxray.exe' '.\main'
if ( -Not $? ) {
    Write-Error "Failed to build wxray.exe."
    exit $lastExitCode
}

Write-Host "Xray-core build script finished."
exit 0 # Explicitly exit with 0 on success