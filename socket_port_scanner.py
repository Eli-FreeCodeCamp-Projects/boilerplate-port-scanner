"""
Simple port scanner using sockets
"""
import socket
import re
import time
from common_ports import ports_and_services

__author__ = "Eli Serra"
__copyright__ = "Copyright 2023, Eli Serra"
__deprecated__ = False
__license__ = "MIT"
__status__ = "Production"
__version__ = "1.0.0"

class SockScanPortError(Exception):
    """InvalidHostError Error Exception."""

class ScanHelper:
    def __init__(self,
                 host: str,
                 port_range: list,
                 verbose: bool = False
                 ):
        """"""
        self.host_type = None

    (HOST_IP, HOST_URL) = range(2)
    REG_IS_IP_TYPE = re.compile(r'^[0-9.]+$')
    REG_IS_IP = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
    REG_IS_URL = re.compile(r'^(?:[0-9A-z.]+.)?[0-9A-z.]+.[a-z]+$')

    @staticmethod
    def get_host_name(ip_address: str) -> str:
        """Test if is valid ip adress"""
        result = None
        try:
            result = socket.gethostbyaddr(ip_address)[0]
        except Exception:
            result = None
        return result
    
    @staticmethod
    def get_ip_address(host_name: str) -> str:
        """Test if is valid ip adress"""
        result = None
        try:
            result = socket.gethostbyname(host_name)
        except Exception:
            result = None
        return result

    @staticmethod
    def is_valid_ip(ip_address: str) -> bool:
        """Test if is valid ip adress"""
        return ScanHelper.REG_IS_IP.match(ip_address)

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Test if is valid url"""
        return ScanHelper.REG_IS_URL.match(url)

    @staticmethod
    def get_host_type(host: str) -> str:
        """Get host type (ip or url)"""
        res = ScanHelper.HOST_URL
        if ScanHelper.REG_IS_IP_TYPE.match(host):
            res = ScanHelper.HOST_IP
        return res
    
    @staticmethod
    def is_valid_host(host: str) -> str:
        """Get verbose format from scan result."""
        host_type = ScanHelper.get_host_type(host)
        if host_type == ScanHelper.HOST_IP:
            if not ScanHelper.is_valid_ip(host):
                raise SockScanPortError("Error: Invalid IP address")
        elif host_type == ScanHelper.HOST_URL:
            if not ScanHelper.is_valid_url(host):
                raise SockScanPortError("Error: Invalid hostname")
        else:
            raise SockScanPortError("Error: Invalid hostname")
        return True

    @staticmethod
    def is_valid_port(port: int) -> bool:
        """Test if is valid url"""
        return isinstance(port, int) \
            and 0 <= port <= 65535

    @staticmethod
    def is_valid_port_range(ports: list) -> bool:
        """Test if is valid url"""
        return isinstance(ports, list) \
            and len(ports) == 2 \
            and ScanHelper.is_valid_port(ports[0]) \
            and ScanHelper.is_valid_port(ports[1])

    @staticmethod
    def get_host_info(host: str) -> tuple:
        """Get verbose format from scan result."""
        host_type = ScanHelper.get_host_type(host)
        if host_type == ScanHelper.HOST_IP:
            host_name = ScanHelper.get_host_name(host)
            ip_addr = host
        else:
            host_name = host
            ip_addr = ScanHelper.get_ip_address(host)
        
        return (host_name, ip_addr)

    @staticmethod
    def get_verbose_header(host: str) -> str:
        """Get verbose header from host."""
        (host_name, ip_addr) = ScanHelper.get_host_info(host)
        if host_name is not None and ip_addr is not None:
            result = "Open ports for %s (%s)\n" % (host_name, ip_addr)
        elif host_name is not None:
            result = "Open ports for %s\n" % (host_name)
        else:
            result = "Open ports for %s\n" % (ip_addr)
        
        return result
    
    @staticmethod
    def get_verbose_scan(scan: list) -> str:
        """Get verbose format from scan result."""
        result = ""
        if isinstance(scan, list) and len(scan) > 0:
            for key, port in enumerate(scan):
                nb_spaces = 9 - len(str(port))
                spacer = " " * nb_spaces
                if key > 0:
                    result += '\n'
                if port in ports_and_services:
                    result += "%s%s%s" % (
                        port,
                        spacer,
                        ports_and_services.get(port)
                    )
                else:
                    result += "%s%s%s" % (port, spacer, "Unkwonwn")
        return result

    @staticmethod
    def verbose_format(scan: list, host: str) -> str:
        """Get verbose format from scan result."""
        result = ScanHelper.get_verbose_header(host)
        result += "PORT     SERVICE\n"
        result += ScanHelper.get_verbose_scan(scan)
        return result

class SocketPortScanner:

    def __init__(self,
                 timeout: int or float = 3,
                 wait: int or float = 0.2,
                 debug: bool = False
                 ):
        """"""
        self.sock = None
        self.timeout = 3
        self.wait = 0.2
        self.debug = False
        self.host_type = None

            
    def init_socket(self):
        """"""
        # creating the socket object
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)    

    def close_socket(self) -> bool:
        """"""
        result = False
        try:
            self.sock.close()
            result = True
        except Exception:
            result = False
        return result

    def is_port_open(self, host: str, port: int) -> bool:
        """Test if the port is open"""
        if not ScanHelper.is_valid_port(port):
            raise SockScanPortError("Error: Invalid Port number. port : %s" % port)
        try:
            code = self.sock.connect_ex((host, port))
            result = code == 0            
        except socket.gaierror as ex:
            print(
              "Is port Error - host : ", host, 
              " - port : ", port, " - error : ", str(ex))
            if self.host_type == ScanHelper.HOST_IP:
                    raise SockScanPortError("Error: Invalid IP address")
            else:
                raise SockScanPortError("Error: Invalid hostname")
                
            result = False
        return result
    
    def scan_ports(self, host: str, port_range: list) -> list:
        """Test port range status from host"""
        result = []
        if not ScanHelper.is_valid_port_range(port_range):
            raise SockScanPortError("Error: Invalid ports range. port_range : ", str(port_range))
        
        if ScanHelper.is_valid_host(host):
            self.host_type = ScanHelper.get_host_type(host)
            for port in range(port_range[0], port_range[1]+1):
                try:
                    self.init_socket()
                    if self.is_port_open(host, port) is True:
                        result.append(port)

                    self.close_socket()
                    time.sleep(self.wait)
                except SockScanPortError as ex:
                    self.close_socket()
                    raise SockScanPortError(ex)
                except Exception as ex:
                    print("scan_ports Error : ", str(ex))
                    self.close_socket()
        return result
    
    def run(self, host: str, port_range: list, verbose: bool = False):
        """"""
        scan = self.scan_ports(host, port_range)
        if verbose is True:
            scan = ScanHelper.verbose_format(scan, host)
        return scan