@echo off
REM cades — CLI wrapper for the CAdES B-LT fat jar

set "DIR=%~dp0"
set "JAR=%DIR%cades-lt-demo-1.0.0-SNAPSHOT-fat.jar"

if not exist "%JAR%" (
  for %%p in ("%LOCALAPPDATA%\cades" "C:\Program Files\cades") do if exist "%%p\cades-lt-demo-1.0.0-SNAPSHOT-fat.jar" set "JAR=%%p\cades-lt-demo-1.0.0-SNAPSHOT-fat.jar"
)

java -jar "%JAR%" %*