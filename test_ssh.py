from ams import *
import pytest

user, password = "user", "password"
SSH_ENABLED = ["10.170.19.111", user, password]
NO_PING = ["172.16.255.254", user, password]
SSH_DISABLED = [Tools.get_ip_address(),user,password]
SSH_WRONG_LOGIN = ["10.170.19.111", "wrong", "login"]

class TestSSH():
    def test_ssh_enabled_no_ping(self):
        try:
            ssh = SSH(NO_PING[0], NO_PING[1], NO_PING[2])
            ssh.close()
            raise
        except Exc.NoPingError:
            pass

    def test_ssh_enabled_no_ping_cm(self):
        try:
            with CM.ssh(NO_PING[0], NO_PING[1], NO_PING[2]) as ssh:
                pass
            raise
        except Exc.NoPingError:
            pass

    def test_ssh_enabled_ping(self):
        ssh = SSH(SSH_ENABLED[0],SSH_ENABLED[1],SSH_ENABLED[2])
        ssh.close()

    def test_ssh_enabled_ping_cm(self):
        with CM.ssh(SSH_ENABLED[0],SSH_ENABLED[1],SSH_ENABLED[2]) as ssh:
            pass

    def test_ssh_disabled(self):
        try:
            ssh = SSH(SSH_DISABLED[0],SSH_DISABLED[1],SSH_DISABLED[2])
            ssh.close()
            raise
        except Exc.SSHError:
            pass

    def test_ssh_disabled_cm(self):
        try:
            with SSH(SSH_DISABLED[0],SSH_DISABLED[1],SSH_DISABLED[2]) as ssh:
                pass
            raise
        except Exc.SSHError:
            pass

    def test_ssh_wrong_login(self):
        try:
            ssh = SSH(SSH_WRONG_LOGIN[0],SSH_WRONG_LOGIN[1],SSH_WRONG_LOGIN[2])
            ssh.close()
            raise
        except Exc.SSHError:
            pass

    def test_ssh_wrong_login_cm(self):
        try:
            with SSH(SSH_WRONG_LOGIN[0],SSH_WRONG_LOGIN[1],SSH_WRONG_LOGIN[2]) as ssh:
                pass
            raise
        except Exc.SSHError:
            pass

    def test_ssh_command(self):
        ssh = SSH(SSH_ENABLED[0], SSH_ENABLED[1], SSH_ENABLED[2])
        ssh.command("ls")
        ssh.close()

    def test_ssh_command_cm(self):
        with CM.ssh(SSH_ENABLED[0],SSH_ENABLED[1],SSH_ENABLED[2]) as ssh:
            ssh.command("ls")

    def test_ssh_command_shell(self):
        ssh = SSH(SSH_ENABLED[0], SSH_ENABLED[1], SSH_ENABLED[2],shell=True,shell_key="")
        ssh.command("ls")
        ssh.close()

    def test_ssh_command_shell_cm(self):
        with CM.ssh(SSH_ENABLED[0],SSH_ENABLED[1],SSH_ENABLED[2],shell=True,shell_key="") as ssh:
            ssh.command("ls")