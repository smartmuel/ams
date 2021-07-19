
import os, socketserver, threading, logging, requests, paramiko
from time import sleep, perf_counter
from inspect import currentframe, getframeinfo
from sys import exc_info
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.keys import Keys
from bps_restpy.bps_restpy_v1.bpsRest import BPS

cwd = os.getcwd()

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
            """

            :param url: The URL
            """
            self.driver = Chrome(url=url)

        def __enter__(self):
            return self.driver

        def __exit__(self, type, value, traceback):
            self.driver.close()

    # SSH Context Manager
    class ssh(object):
        def __init__(self, host: str, user: str, password: str, pingf: bool = True):
            """

            :param host: host to ssh
            :param user: username for the ssh
            :param password: password for the ssh
            :param pingf: flag to ping
            """
            self.ssh = SSH(host=host, user=user, password=password, pingf=pingf)

        def __enter__(self):
            return self.ssh

        def __exit__(self, type, value, traceback):
            self.ssh.close()

    # Telnet Context Manager
    class telnet(object):
        def __init__(self, host: str, user: str, password: str, pingf: bool = True, ask_user: str = b"User:", ask_pass: str = b"Password:", cli_sign: str = b"#"):
            """

            :param host: host to telnet
            :param user: username for the telnet
            :param password: password for the telnet
            :param pingf: flag to ping
            :param ask_user: Read until a given byte string of the username statement
            :param ask_pass: Read until a given byte string of the password statement
            :param cli_sign: Read until a given byte string of the cli sign
            """
            self.telnet = Telnet(host=host, user=user, password=password, pingf=pingf, ask_user=ask_user, ask_pass=ask_pass, cli_sign=cli_sign)

        def __enter__(self):
            return self.telnet

        def __exit__(self, type, value, traceback):
            self.telnet.close()

    # Syslog server Context Manager
    class syslog(object):
        def __init__(self, name: str = "syslog", ip: str = get_ip_address()):
            """

            :param name: Syslog log file name
            :param ip: The IP address to listen to, the default ip would be the ip that can connect to 8.8.8.8
            """
            self.syslog = Syslog(name=name,ip=ip)

        def __enter__(self):
            return self.syslog

        def __exit__(self, type, value, traceback):
            self.syslog.close()

    # context manager for Vision API
    class api(object):
        def __init__(self, vision: str, user: str, password: str):
            """

            :param vision: Vision IP
            :param user: Username
            :param password: Password
            """
            self.api = API(vision=vision, user=user, password=password)

        def __enter__(self):
            return self.api

        def __exit__(self, type, value, traceback):
            self.api.close()

    # context manager for Breaking Point
    class bp(object):
        def __init__(self, test: str, ip: str, user: str, password: str, slot : int = 0, ports : list = []):
            """

            :param test: Test name
            :param ip: BP IP
            :param user: BP username
            :param password: BP password
            :param slot: Slot number of the ports to reserve
            :param ports: Ports to reserve as list, example: [1,2]
            :return: None
            """
            BP.start(test=test,ip=ip,user=user,password=password,slot=slot,ports=ports)
            self.ip, self.user, self.password = ip, user, password
            
        def __enter__(self):
            return self
        
        def __exit__(self, type, value, traceback):
            BP.stop(ip=self.ip,user=self.user,password=self.password)

    # class for context manager tools like: cd( change directory ), timer , etc..
    class tools(object):
        # context manager for changing directory
        class cd(object):
            def __init__(self, path: str):
                """

                :param path: The path of the directory to change to.
                """
                os.chdir(path)

            def __enter__(self):
                return self

            def __exit__(self, type, value, traceback):
                os.chdir(cwd)

        # context managers timer
        class timer(object):
            def __init__(self, TIME: int, delay: int = 0):
                """

                :param TIME: The time range the timer should at least end, if the code within take more time then it would end after the code ended.
                :param delay: Delay before the code running within
                """
                self.TIME = TIME
                self.start = perf_counter()
                sleep(delay)

            def __enter__(self):
                return self

            def __exit__(self, type, value, traceback):
                try:
                    sleep(self.TIME - int(perf_counter() - self.start))
                except:pass#silenced

# class that contain all the automation functions with Chrome.
class Chrome(object):
    """
    Chrome Automation.
    """

    def __init__(self, url: str = ""):
        """

        :param url: The URL
        """
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
            import chromedriver_autoinstaller
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
                    myElem = self.driver.find_element_by_xpath(elem)
                    myElem.click()
                    myElem.clear()
                    myElem.send_keys(text)
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
        flag = ping(host) if pingf else True
        if flag:
            self.host, self.user, self.password, self.pingf = host, user, password, pingf
            self.ssh_connect(host, user, password)
        else:
            print(getframeinfo(currentframe()).lineno, "invalid host or no ping to host")
            self.close()

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
                    self.ssh.connect(hostname=host, port=port, username=user, password=password)
                    break
                except TimeoutError:
                    if self.pingf:
                        print(getframeinfo(currentframe()).lineno, "invalid host or no ping to host")
                        self.close()
                except:pass#Silenced
        except:
            print(getframeinfo(currentframe()).lineno, "Unexpected error:", exc_info()[0], exc_info()[1])
            print(getframeinfo(currentframe()).lineno, "ssh_connect failed")
            self.close()

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

# class for Telnet
class Telnet(object):
    """
    Class for Telnet
    """

    def __init__(self, host: str, user: str, password: str, pingf: bool = True, ask_user: str = b"User:", ask_pass: str = b"Password:", cli_sign: str = b"#"):
        """

        :param host: host to telnet
        :param user: username for the telnet
        :param password: password for the telnet
        :param pingf: flag to ping
        :param ask_user: Read until a given byte string of the username statement
        :param ask_pass: Read until a given byte string of the password statement
        :param cli_sign: Read until a given byte string of the cli sign
        """
        flag = ping(host) if pingf else True
        if flag:
            try:
                import telnetlib
                self.tn = telnetlib.Telnet()
                self.tn.open(host)
                self.tn.read_until(ask_user)
                self.tn.write(user.encode('ascii') + b"\n")
                self.tn.read_until(ask_pass)
                self.tn.write(password.encode('ascii') + b"\n")
                self.tn.read_until(cli_sign, 60).decode('utf-8')
            except:
                print(getframeinfo(currentframe()).lineno, "Unexpected error:", exc_info()[0], exc_info()[1])
                self.close()
        else:
            print(getframeinfo(currentframe()).lineno, "invalid host or no ping to host")
            self.close()

    def command(self, command: str):
        """

        :param command: the command
        :return: returns the output of the command
        """

        try:
            self.tn.write(command.encode('ascii') + b"\n")
            output = self.tn.read_until(b"#", 30).decode('utf-8')
            return output
        except:
            print(getframeinfo(currentframe()).lineno, "Unexpected error:", exc_info()[0], exc_info()[1])
            self.close()

    def close(self):
        try:
            self.tn.close()
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
            # print(getframeinfo(currentframe()).lineno,"%s : " % self.client_address[0], self.data)
            logging.info(self.data)

    def __init__(self, name: str = "syslog", ip: str = get_ip_address()):
        """

        :param name: Syslog log file name
        :param ip: The IP address to listen to, the default ip would be the ip that can connect to 8.8.8.8
        """
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

# class for Breaking Point
class BP(object):
    """
    Class for Breaking Point
    """

    test_id = ""

    @staticmethod
    def start(test: str, ip: str, user: str, password: str, slot : int = 0, ports : list = []):
        """

        :param test: Test name
        :param ip: BP IP
        :param user: BP username
        :param password: BP password
        :param slot: Slot number of the ports to reserve
        :param ports: Ports to reserve as list, example: [1,2]
        :return: None
        """
        bps = BPS(ip, user, password)
        # login
        bps.login()
        if slot:
            bps.reservePorts(slot=slot,
                             portList=ports,
                             group=1, force=True)
        # showing current port reservation state
        bps.portsState()
        BP.test_id = bps.runTest(modelname=test, group=1)
        bps.logout()

    @staticmethod
    def stop(ip: str, user: str, password: str, csv: bool = False):
        """

        :param ip: BP IP
        :param user: BP username
        :param password: BP password
        :param csv: Export csv report
        :return: None
        """
        try:
            bps = BPS(ip, user, password)
            # login
            bps.login()
            # stopping test
            bps.stopTest(testid=BP.test_id)
            # logging out
            if csv:
                bps.exportTestReport(BP.test_id, "Test_Report.csv", "Test_Report")
        except:
            print(getframeinfo(currentframe()).lineno, "Unexpected error:", exc_info()[0], exc_info()[1])
        finally:
            try:
                bps.logout()
            except:
                pass  # Silenced

# class for Vision API
class API(object):
    """
    Login/Logout/Get from Vision with REST API
    """
    # flag that indicate the success of the login to vision
    flag = False

    def __init__(self, vision: str, user: str, password: str):
        """

        :param vision: Vision IP
        :param user: Username
        :param password: Password
        """
        self.vision = vision
        url = f"https://{self.vision}/mgmt/system/user/login"
        fill_json = {"username": user, "password": password}
        response = requests.post(url, verify=False, data=None, json=fill_json)
        # self.flag = response.status_code
        self.cookie = response.cookies
        self.flag = False if "jsessionid" not in response.text else True

    def get(self, url: str):
        response = requests.get(url, verify=False, data=None, cookies=self.cookie)
        return response.json()
    
    def post(self, url: str, json: dict):
        response = requests.post(url, verify=False, data=None, json=json, cookies=self.cookie)
        return response.json()

    def close(self):
            url = f"https://{self.vision}/mgmt/system/user/logout"
            response = requests.post(url, verify=False, cookies=self.cookie)
            # self.flag = response.status_code
            
"""class Script(object):
    
    @staticmethod
    def DP_upgrade():"""
            