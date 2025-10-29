Set-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)

git clone https://github.com/XTLS/Xray-core.git -b 'v1.8.10' src
if ( -Not $? ) {
    exit $lastExitCode
}
Set-Location src

$Env:CGO_ENABLED='0'
$Env:GOROT_FINAL='/usr'

$Env:GOOS='windows'
$Env:GOARCH='amd64'
go mod tidy
go build -o ..\..\release\xray.exe -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
exit $lastExitCode
