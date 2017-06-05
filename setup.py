from distutils.core import setup
import py2exe, sys, os

sys.argv.append('py2exe')

setup(
    options={'py2exe': {'bundle_files': 1, 'compressed': True}},
    windows=[{'script': "installer.py"}],
    zipfile=None)

# setup(
#     options={'py2exe': {'bundle_files': 1, 'compressed': True, "includes": ["sip"]}},
#     windows=[{'script': "client_encryption.py"}],
#     zipfile=None)
#
# setup(
#      options={'py2exe': {'bundle_files': 1, 'compressed': True, "includes": ["sip"]}},
#      windows=[{'script': "client_decryption.py"}],
#      zipfile=None)
