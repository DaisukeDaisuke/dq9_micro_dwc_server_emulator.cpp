
@echo off
setlocal

REM Docker build
docker build . -t ncwt:local

REM Create container and capture container ID
for /f %%i in ('docker create ncwt:local') do set CID=%%i

REM Copy files from container
docker cp %CID%:/dummy-certs/ .\dummy-certs

REM Remove container
docker rm %CID%

endlocal
