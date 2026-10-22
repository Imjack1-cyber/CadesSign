@echo off
REM cades — CLI wrapper for the CAdES B-LT fat jar

set "DIR=%~dp0"
set "JAR=%DIR%cades-lt.jar"

if not exist "%JAR%" (
  for %%p in ("%LOCALAPPDATA%\cades" "C:\Program Files\cades") do if exist "%%p\cades-lt.jar" set "JAR=%%p\cades-lt.jar"
)

java -jar "%JAR%" %*