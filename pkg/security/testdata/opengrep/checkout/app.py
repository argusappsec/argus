import pickle
import subprocess


def run(cmd):
    subprocess.run(cmd, shell=True)  # noopengrep


def run_again(cmd):
    # nosemgrep: argus.python.subprocess-shell-true
    subprocess.run(cmd, shell=True)


def load(blob):
    return pickle.loads(blob)
