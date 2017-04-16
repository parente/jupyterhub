import os
import sys

c.JupyterHub.services = [
    {
        'name': 'whoami',
        'url': 'http://127.0.0.1:10101',
        'command': [sys.executable, './whoami.py'],
        'admin': True
    }
]
c.Authenticator.admin_users = {'parente'}
c.JupyterHub.admin_access = True
