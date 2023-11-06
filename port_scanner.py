from socket_port_scanner import SockScanPortError
from socket_port_scanner import SocketPortScanner

def get_open_ports(target, port_range, verbose=False):
    result = []
    try:
        scanner = SocketPortScanner()
        result = scanner.run(target, port_range, verbose)
    except SockScanPortError as ex:
        result = str(ex)
    return result
