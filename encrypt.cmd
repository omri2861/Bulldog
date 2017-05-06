:: This File should be ran when the user clicks the file it wants to encrypt.
:: The registry key should store the following command: "cmd /k (path)\bulldog.cmd %1
:: Note: Like that, the cmd console still pops up but disappears shortly. I didn't find any way to take care of it besides turning the python file to an executable.
start pythonw.exe F:\Cyber\Bulldog\src\client_encryption.py %1