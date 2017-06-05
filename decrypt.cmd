:: This File should be ran when the user clicks the file it wants to decrypt.
:: The registry key should store the following command: "cmd /k (path)\decrypt.cmd %1"
:: Note: Like that, the cmd console still pops up but disappears shortly. I didn't find any way to take care of it besides turning the python file to an executable.
@echo off
start pythonw.exe F:\Cyber\Bulldog\src\client_decryption.py %1