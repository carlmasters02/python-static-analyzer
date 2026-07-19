"""DELIBERATELY VULNERABLE sample — command injection.

Do not run this. It exists so the analyzer has something to catch.
Each function is labeled VULNERABLE or SAFE so we can check the tool's
answers against ground truth later.
"""

import os
import subprocess


def ping_host_vulnerable():
    # VULNERABLE: user input flows straight into a shell command.
    host = input("host to ping: ")
    os.system("ping -c 1 " + host)


def backup_vulnerable(filename):
    # VULNERABLE: 'filename' is an untrusted parameter used in a shell string.
    subprocess.call("tar -czf backup.tar.gz " + filename, shell=True)


def list_dir_safe():
    # SAFE: the command is a hardcoded constant, no user data involved.
    os.system("ls -la /var/log")


def ping_host_safe():
    # SAFE: arguments passed as a list with shell=False — no shell parsing,
    # so 'host' cannot inject extra commands.
    host = input("host to ping: ")
    subprocess.run(["ping", "-c", "1", host], shell=False)
