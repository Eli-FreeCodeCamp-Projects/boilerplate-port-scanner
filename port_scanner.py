import socket
import re

class InvalidParamsError(Exception):
    """InvalidIpError Error Exception."""

class PortScanner:

    def __init__(self, host, port_range, verbose=False):
        """"""
        self.sock = None
        self.host = None
        self.host_type = None
        self.port_range = None
        self.verbose = False
        self.init_params(host, port_range, verbose)
    
    (HOST_IP, HOST_URL) = range(2)
    REG_IS_IP_TYPE = re.compile(r'^[0-9.]+$')
    REG_IS_IP = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
    REG_IS_URL = re.compile(r'^(?:[0-9A-z.]+.)?[0-9A-z.]+.[a-z]+$')

    def is_ready(self):
        return self.sock is not None\
            and self.host is not None\
            and self.port_range is not None\
    
    def init_params(self, host, port_range, verbose=False):
        """"""
        self.host_type = PortScanner.get_host_type(host)
        if self.host_type == PortScanner.HOST_IP:
            if not PortScanner.is_valid_ip(host):
                raise InvalidParamsError("Error: Invalid IP address")
        elif self.host_type == PortScanner.HOST_URL:
            if not PortScanner.is_valid_url(host):
                raise InvalidParamsError("Error: Invalid hostname")
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
        self.sock.settimeout(5)

    def is_port_open(self, port) -> bool:
        """Test if the port is open"""
        return not self.sock.connect_ex((self.host, port))
    
    def scan_ports(self) -> bool:
        """Test if the port is open"""
        
        res = None
        if self.is_ready():
            res = []
            for port in self.port_range:
                if self.is_port_open(port):
                    res.append(port)
        return res
    
    def get_verbose(self, scan):
        """"""
        return """
        Open ports for %s (%s)
        PORT\tSERVICE
        """ % (self.host, self.host)

    def run(self):
        """"""
        self.init_socket()
        scan = self.scan_ports()
        if isinstance(scan, list) and self.verbose is True:
            scan = self.get_verbose()
        return scan



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
        result = scanner.run()
    except InvalidParamsError as ex:
        result = str(ex)


    return result