"""
This file will install the Bulldog program.
It will create file associations.
"""

import _winreg
import os

LOCKED_EXTENSION = ".bef"
CLASSES_ROOT = "HKEY_CLASSES_ROOT"
DECRYPTION_PROGRAM_NAME = "decryptionMain.exe"
ENCRYPTION_PROGRAM_NAME = "encryptionMain.exe"
DECRYPTION_PROGRAM_PATH = os.getcwd() + os.sep + DECRYPTION_PROGRAM_NAME
ENCRYPTION_PROGRAM_PATH = os.getcwd() + os.sep + ENCRYPTION_PROGRAM_NAME
DECRYPTION_PROGRAM_COMMAND = '"%s" "' % (DECRYPTION_PROGRAM_PATH) + '%1"'
ENCRYPTION_PROGRAM_COMMAND = '"%s" "' % (ENCRYPTION_PROGRAM_PATH) + '%1"'
BULLDOG_DECRYPTION = "BulldogDecrypt"
DEFAULT_VALUE = ""
SHELL = "\\shell"
OPEN = "\\open"
COMMAND = "\\command"
BULLDOG_LOCK = "\\bulldog_lock"
ALL_FILES = "*"
ENCRYPTION_TEXT = "Lock file using Bulldog..."
ENCRYPTION_REG_PATH = r"*\shell\bulldog_lock"
ENCRYPTION_DIRECTORY_TEXT = "Lock this folder using Bulldog..."
DIRECTORY_REG_PATH = "Directory"
DECRYPTION_DIRECTORY_TEXT = "Unlock this folder using Bulldog..."
BULLDOG_UNLOCK = "\\bulldog_unlock"


def set_reg(reg_path, name, value):
    try:
        registry_key = _winreg.CreateKey(_winreg.HKEY_CLASSES_ROOT, reg_path)
        _winreg.SetValueEx(registry_key, name, 0, _winreg.REG_SZ, value)
        _winreg.CloseKey(registry_key)
        return True
    except WindowsError as err:
        print err
        return False


def create_decryption_keys():
    set_reg(LOCKED_EXTENSION, DEFAULT_VALUE, BULLDOG_DECRYPTION)
    set_reg(DIRECTORY_REG_PATH+SHELL+BULLDOG_LOCK, DEFAULT_VALUE, ENCRYPTION_DIRECTORY_TEXT)
    set_reg(BULLDOG_DECRYPTION, DEFAULT_VALUE, "")
    set_reg(BULLDOG_DECRYPTION + SHELL, DEFAULT_VALUE, "")
    set_reg(BULLDOG_DECRYPTION + SHELL + OPEN, DEFAULT_VALUE, "")
    set_reg(BULLDOG_DECRYPTION + SHELL + OPEN + COMMAND, DEFAULT_VALUE, DECRYPTION_PROGRAM_COMMAND)

    set_reg(DIRECTORY_REG_PATH+SHELL+BULLDOG_UNLOCK, DEFAULT_VALUE, DECRYPTION_DIRECTORY_TEXT)
    set_reg(DIRECTORY_REG_PATH+SHELL+BULLDOG_UNLOCK+COMMAND, DEFAULT_VALUE, DECRYPTION_PROGRAM_COMMAND)


def main():
    """
    The main function of the program. Will install the system.
    :return: None
    """
    set_reg(ENCRYPTION_REG_PATH, DEFAULT_VALUE, ENCRYPTION_TEXT)
    set_reg(ENCRYPTION_REG_PATH+COMMAND, DEFAULT_VALUE, ENCRYPTION_PROGRAM_COMMAND)

    set_reg(DIRECTORY_REG_PATH+SHELL+BULLDOG_LOCK, DEFAULT_VALUE, ENCRYPTION_TEXT)
    set_reg(DIRECTORY_REG_PATH+SHELL+BULLDOG_LOCK+COMMAND, DEFAULT_VALUE, ENCRYPTION_PROGRAM_COMMAND)

    create_decryption_keys()


if __name__ == '__main__':
    main()
