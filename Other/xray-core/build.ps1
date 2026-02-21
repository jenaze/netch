Set-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)

git clone https://github.com/XTLS/Xray-core.git src
if ( -Not $? ) {
    exit $lastExitCode
}
Set-Location src

$Env:CGO_ENABLED='0'
$Env:GOROOT_FINAL='/usr'

$Env:GOOS='windows'
$Env:GOARCH='amd64'
go get -u ./...
go mod tidy
go build -a -trimpath -asmflags '-s -w' -ldflags '-s -w -buildid=' -o '..\..\release\xray.exe' '.\main'
exit $lastExitCode
