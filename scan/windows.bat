@echo off
for /f "delims=" %%a in (list.txt) do ping -n 1 %%a >nul && (echo %%a
ok >> ok.txt) || (echo %%a tk >> fail.txt)
pause