import socket
import re
import time
from common_ports import ports_and_services

class InvalidParamsError(Exception):
    """InvalidIpError Error Exception."""

class PortScanner:

    def __init__(self, host, port_range, verbose=False):
        """"""
        self.sock = None
        self.host = None
        self.host_name = None
        self.ip_addr = None
        self.host_type = None
        self.port_range = None
        self.verbose = False
        
        self.init_params(host, port_range, verbose)
    
    (HOST_IP, HOST_URL) = range(2)
    REG_IS_IP_TYPE = re.compile(r'^[0-9.]+$')
    REG_IS_IP = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
    REG_IS_URL = re.compile(r'^(?:[0-9A-z.]+.)?[0-9A-z.]+.[a-z]+$')

    def is_ready(self):
        return self.host is not None\
            and self.port_range is not None\
    
    def init_params(self, host, port_range, verbose=False):
        """"""
        self.host_type = PortScanner.get_host_type(host)
        if self.host_type == PortScanner.HOST_IP:
            if not PortScanner.is_valid_ip(host):
                raise InvalidParamsError("Error: Invalid IP address")
            else:
                self.host_name = PortScanner.get_host_name(host)
                self.ip_addr = host
        elif self.host_type == PortScanner.HOST_URL:
            if not PortScanner.is_valid_url(host):
                raise InvalidParamsError("Error: Invalid hostname")
            else:
                self.host_name = host
                self.ip_addr = PortScanner.get_ip_address(host)
        else:
            raise InvalidParamsError("Error: Invalid hostname")
        
        if not PortScanner.is_valid_port_range(port_range):
            raise InvalidParamsError("Error: Invalid ports range.")
        self.host = host
        self.port_range = port_range
        if verbose is True:
            self.verbose = True
        
    def init_socket(self):
        """"""
        # creating the socket object
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(3)

    def is_port_open(self, port) -> bool:
        """Test if the port is open"""
        result = False
        try:
            code = self.sock.connect_ex((self.host, port))
            result = code == 0            
        except Exception as ex:
            print(
              "Is port Error - host : ", self.host, 
              " - port : ", port, " - error : ", str(ex))
            if str(ex) == "[Errno -2] Name or service not known":
                if self.host_type == PortScanner.HOST_URL:
                    raise InvalidParamsError("Error: Invalid hostname")
                else:
                    raise InvalidParamsError("Error: Invalid IP address")
            result = False
        return result

    def scan_ports(self) -> bool:
        """Test if the port is open"""
        result = None
        
        if self.is_ready():
            result = []
            for port in range(self.port_range[0], self.port_range[1]+1):
                try:
                    self.init_socket()
                    if self.is_port_open(port) is True:
                        # print("port is open ", port)
                        result.append(port)
                    self.close_socket()
                    time.sleep(0.2)
                except InvalidParamsError as ex:
                    self.close_socket()
                    raise InvalidParamsError(ex)
                except Exception as ex:
                    print("scan_ports Error : ", str(ex))
                    self.close_socket()
        return result
    
    def get_verbose(self, scan):
        """"""
        if self.host_name is not None and self.ip_addr is not None:
            result = "Open ports for %s (%s)\n"% (self.host_name, self.ip_addr)
        elif self.host_name is not None:
            result = "Open ports for %s\n"% (self.host_name)
        else:
            result = "Open ports for %s\n"% (self.ip_addr)
        
        result += "PORT     SERVICE\n"

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
                    result += "%s%s%s" % (port, spacer, "UNKNWOWN")
        return result

    def run(self):
        """"""
        scan = self.scan_ports()
        if self.verbose is True:
            scan = self.get_verbose(scan)
        return scan

    def close_socket(self):
        """"""
        result = False
        try:
            self.sock.close()
            result = True
        except Exception:
            result = "Unknown"
        return result

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
        return PortScanner.REG_IS_IP.match(ip_address)

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Test if is valid url"""
        return PortScanner.REG_IS_URL.match(url)

    @staticmethod
    def get_host_type(host: str) -> str:
        """Get host type (ip or url)"""
        res = PortScanner.HOST_URL
        if PortScanner.REG_IS_IP_TYPE.match(host):
            res = PortScanner.HOST_IP
        return res
    
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
            and PortScanner.is_valid_port(ports[0]) \
            and PortScanner.is_valid_port(ports[1])

def get_open_ports(target, port_range, verbose=False):
    result = []
    try:
        scanner = PortScanner(target, port_range, verbose)
        result =scanner.run()
    except InvalidParamsError as ex:
        result = str(ex)


    return result