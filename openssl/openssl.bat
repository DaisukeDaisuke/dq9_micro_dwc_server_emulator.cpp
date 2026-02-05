
@echo off
setlocal

REM Docker build
docker build . -t openssl111w-mingw:local ^
  --build-arg OPENSSL_TAG=OpenSSL_1_1_1w ^
  --build-arg OPENSSL_DIR=openssl-1.1.1w

REM Create container and capture container ID
for /f %%i in ('docker create openssl111w-mingw:local') do set CID=%%i

REM Copy files from container
docker cp %CID%:/out/openssl .\openssl

REM Remove container
docker rm %CID%

endlocal
