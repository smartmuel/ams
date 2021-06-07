
import os ,paramiko, socketserver, threading, logging
from time import sleep
from inspect import currentframe, getframeinfo
from sys import exc_info
import chromedriver_autoinstaller
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.keys import Keys


cwd = os.getcwd()

# context managers for changing directory
class cd(object):
    def __init__(self, path: str):
        os.chdir(path)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        os.chdir(cwd)

# the IP that can connect to the specified destination, 8.8.8.8 is the default
def get_ip_address(dest: str ="8.8.8.8") -> str:
    """
    :param dest: The destination ip to reach from the machine
    :return: The ip address that can connect to the specified destination
    """
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((dest, 80))
    return s.getsockname()[0]


# ping command, returns True/False
def ping(host: str) -> bool:
    """
    :param host: can be ip or host name
    :return: True/False
    """
    from platform import system
    param = '-n' if system().lower() == 'windows' else '-c'
    command = f"ping {param} 1 {host}"
    response = os.popen(command).read().lower()
    return 'unreachable' not in response and "100%" not in response


# Context Managers Class For All The Functions That Need To Be Closed.
class CM(object):
    # Chrome Context Manager
    class chrome(object):
        def __init__(self, url: str = ""):
            self.driver = Chrome(url=url)

        def __enter__(self):
            return self.driver

        def __exit__(self, type, value, traceback):
            self.driver.close()

    # SSH Context Manager
    class ssh(object):
        def __init__(self, host: str, user: str, password: str, pingf: bool = True):
            self.ssh = SSH(host=host, user=user, password=password)

        def __enter__(self):
            return self.ssh

        def __exit__(self, type, value, traceback):
            self.ssh.close()

    # Syslog server Context Manager
    class syslog(object):
        def __init__(self, name: str, ip: str = get_ip_address()):
            self.syslog = Syslog(name=name,ip=ip)

        def __enter__(self):
            return self.syslog

        def __exit__(self, type, value, traceback):
            self.syslog.close()

# class that contain all the automation functions with Chrome.
class Chrome(object):
    """
    Chrome Automation.
    """

    def __init__(self, url: str = ""):

        # Opening Chrome Driver
        options = Options()
        options.add_experimental_option("prefs", {
            "download.default_directory": rf"{cwd}",
            "download.prompt_for_download": False,
            "download.directory_upgrade": True,
            "safebrowsing.enabled": True
        })
        options.add_argument('--ignore-certificate-errors')

        try:
            self.driver = webdriver.Chrome(options=options)
        except:
            chromedriver_autoinstaller.install()
            self.driver = webdriver.Chrome(options=options)

        self.url(url)

    def __call__(self):
        return self.driver

    def url(self, url: str):
        try:
            if "://" not in url:
                url = f"https://{url}{(not bool(url)) * 'www.google.com'}"
            self.driver.get(url)
            self.driver.fullscreen_window()
        except:
            print(getframeinfo(currentframe()).lineno, "Unexpected error:", exc_info()[0], exc_info()[1])

    def close(self):
        try:
            self.driver.close()
            self.driver.quit()
        except:
            print(getframeinfo(currentframe()).lineno, "Unexpected error:", exc_info()[0], exc_info()[1])
        finally:
            del self

    def wait(self, elem: str, delay: int = 10, Type: str = By.XPATH) -> bool:
        """
        
        :param elem: The copied element, the element should be in the type that is selected
        :param delay: The delay
        :param Type: The default type is Xpath
        :return: True if the element is existing
        """

        elem = elem.strip()
        flag = True
        try:
            WebDriverWait(self.driver, delay).until(EC.presence_of_element_located((Type, elem)))
        except TimeoutException:
            print(getframeinfo(currentframe()).lineno, "Wait False", elem)
            flag = False
        except:
            print(getframeinfo(currentframe()).lineno, "Unexpected error:", exc_info()[0], exc_info()[1])
            flag = False
        return flag

    def click(self, elem: str, tries: int = 3, delay: int = 3) -> bool:
        """

        :param elem: The copied Xpath element
        :param tries: tries to click
        :param delay: The delay for the wait function
        :return: True if click succeeded
        """

        flag = True
        if self.wait(elem=elem, delay=delay):
            elem = elem.strip()
            for i in range(tries):
                try:
                    self.driver.find_element_by_xpath(elem).click()
                    break
                except:
                    print(getframeinfo(currentframe()).lineno, f"Failed to Click_{str(i)}", elem)
            else:
                flag = False
        else:
            flag = False
        return flag

    def fill(self, elem: str, text: str, enter: bool = False, tries: int = 3, delay: int = 5) -> bool:
        """

        :param elem: The copied Xpath element
        :param text:
        :param enter:
        :param tries:
        :param delay:
        :return:
        """

        flag = True
        if self.wait(elem=elem, delay=delay):
            for i in range(tries):
                try:
                    myElem = self.driver.find_element_by_xpath(elem).click().clear().send_keys(text)
                    if enter:
                        myElem.send_keys(Keys.ENTER)
                    break
                except:
                    print(getframeinfo(currentframe()).lineno, "Unexpected error:", exc_info()[0], exc_info()[1])
                    flag = False
            else:
                flag = False
        else:
            flag = False
        return flag

# class for SSH
class SSH(object):
    """
    Class for SSH
    """

    def __init__(self, host: str, user: str, password: str, pingf: bool = True):
        """

        :param host: host to ssh
        :param user: username for the ssh
        :param password: password for the ssh
        :param pingf: flag to ping
        """

        if ping(host) or not pingf:
            self.host, self.user, self.password = host, user, password
            self.ssh_connect(host, user, password)
        else:
            print(getframeinfo(currentframe()).lineno, "invalid host or no ping to host")
            del self

    def ssh_connect(self, host: str, user: str, password: str, port: int = 22, tries: int = 5):
        """

        :param host: host to ssh
        :param user: username for the ssh
        :param password: password for the ssh
        :param port: port to connect for the ssh, 22 is default
        :param tries: the number of times to try to connect
        """

        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            for i in range(tries):
                try:
                    self.ssh.connect(host, port=port, username=user, password=password)
                    break
                except:pass#Silenced
        except:
            print(getframeinfo(currentframe()).lineno, "Unexpected error:", exc_info()[0], exc_info()[1])
            print(getframeinfo(currentframe()).lineno, "ssh_connect failed")
            del self

    def command(self, command: str, tries: int = 3):
        """
        :param command: the command
        :param tries: the number of times to try to send the command
        :return: returns the output of the command - not working all the time
        """

        for i in range(tries):
            try:
                stdin, stdout, stderr = self.ssh.exec_command(command)
                return stdout.readlines()
            except:
                self.ssh_connect(self.host, self.user, self.password)
        else:
            print(getframeinfo(currentframe()).lineno, "ssh_command failed")

    def close(self):
        try:
            self.ssh.close()
        except:pass#silenced
        del self

# class for Syslog Server
class Syslog(object):
    """
    Class for Syslog Server
    """

    class SyslogUDPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            # socket = self.request[1]
            self.data = str(bytes.decode(self.request[0].strip()))
            # self.match()
            # print(getframeinfo(currentframe()).lineno,"%s : " % self.client_address[0], self.data)
            logging.info(self.data)

        def match(self):
            if self.data:
                pass

    def __init__(self, name: str, ip: str = get_ip_address()):
        self.name,self.ip = name,ip
        t1 = threading.Thread(target=self.Server)
        t1.start()

    # Setting the Syslog server
    def Server(self):
        try:
            logging.basicConfig(level=logging.INFO, format='%(message)s', datefmt='', filename=self.name,
                                filemode='a')
            self.server = socketserver.UDPServer((self.ip, 514), Syslog.SyslogUDPHandler)
            self.server.serve_forever(poll_interval=0.5)
        except (IOError, SystemExit):
            raise
        except KeyboardInterrupt:
            print(getframeinfo(currentframe()).lineno, "Crtl+C Pressed. Shutting down.")

    # Closing the Server
    def close(self):
        try:
            self.server.shutdown()
        except:
            print(getframeinfo(currentframe()).lineno, "Unexpected error:", exc_info()[0], exc_info()[1])
        del self
