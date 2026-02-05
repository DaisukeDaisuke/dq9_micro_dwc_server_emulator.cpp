
@echo off
setlocal

REM Docker build
docker build . -t openssl111w-mingw:local ^
  --build-arg OPENSSL_TAG=openssl-3.0.19 ^
  --build-arg OPENSSL_DIR=openssl-3.0.19

REM Create container and capture container ID
for /f %%i in ('docker create openssl111w-mingw:local') do set CID=%%i

REM Copy files from container
docker cp %CID%:/out/openssl .\openssl

REM Remove container
docker rm %CID%

endlocal
