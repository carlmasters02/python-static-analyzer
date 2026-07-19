"""Labeled benchmark cases — command injection.

Ground truth is encoded on each sink line with a trailing marker
(written as hash-at-VULN / hash-at-SAFE):
    VULN  -> this call IS a real command injection (tool SHOULD flag it)
    SAFE  -> this call is safe          (tool SHOULD NOT flag it)

The scorer (benchmark/score.py) reads these markers, runs the analyzer,
and compares. Keep each sink call on a single line so line numbers match.
"""

import os
import shlex
import subprocess


# ---- Should be caught (true vulnerabilities) ------------------------------

def concat_input():
    host = input("host: ")
    os.system("ping -c 1 " + host)  #@ VULN


def fstring_param(host):
    os.popen(f"ping -c 1 {host}")  #@ VULN


def subprocess_shell_true(user_arg):
    subprocess.call("tar -czf out.tar " + user_arg, shell=True)  #@ VULN


def percent_format():
    target = input()
    os.system("nslookup %s" % target)  #@ VULN


def multi_hop():
    a = input()
    b = "echo " + a
    os.system(b)  #@ VULN


# ---- Should NOT be caught (safe lookalikes) -------------------------------

def constant_command():
    os.system("ls -la /var/log")  #@ SAFE


def list_form_no_shell():
    host = input()
    subprocess.run(["ping", "-c", "1", host], shell=False)  #@ SAFE


def sanitized_with_shlex():
    host = input()
    os.system("ping -c 1 " + shlex.quote(host))  #@ SAFE


def sanitized_with_int():
    seconds = input()
    os.system("sleep " + str(int(seconds)))  #@ SAFE


def string_no_shell():
    # No shell=True, so subprocess treats this as a program name, not a
    # shell command — our tool (correctly, for this class) does not flag it.
    cmd = input()
    subprocess.run(cmd)  #@ SAFE
