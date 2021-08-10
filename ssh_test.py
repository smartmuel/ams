from ams import *
import pytest

SSH_ENABLED=["10.170.19.111", "root", "radware"]

def test_no_ping():
    ssh = SSH(SSH_ENABLED[0], SSH_ENABLED[1], SSH_ENABLED[2])
    ssh.close()

    assert ssh == True