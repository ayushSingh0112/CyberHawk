import socket
import concurrent.futures

def parse_ports_string(port_str):
    ports = set()
    for p in str(port_str).split(','):
        p = p.strip()
        if not p: continue
        if '-' in p:
            try:
                start, end = map(int, p.split('-'))
                # Limit range to avoid massive lockups
                if end - start > 10000: end = start + 10000 
                ports.update(range(start, end + 1))
            except ValueError: pass
        elif p.isdigit():
            ports.add(int(p))
    return sorted(list(ports))

class PortScanner:
    def __init__(self, target_ip, port_str="80,443"):
        self.target_ip = target_ip
        
        if not port_str or port_str.lower() == 'all':
            self.ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
        else:
            self.ports_to_scan = parse_ports_string(port_str)
            if not self.ports_to_scan:
                self.ports_to_scan = [80] # Fallback

    def scan_port(self, port):
        """Attempts to connect to a port and retrieve a banner/service version."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((self.target_ip, port))
            
            if result == 0:
                # Port is open, try banner grabbing
                banner = "Unknown Service"
                service = "tcp"
                
                # Guess standard services
                if port == 80 or port == 8080: service = "http"
                elif port == 443 or port == 8443: service = "https"
                elif port == 22: service = "ssh"
                elif port == 21: service = "ftp"
                elif port == 3306: service = "mysql"
                
                try:
                    if service in ['http', 'https']:
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    else:
                        sock.sendall(b"\r\n")
                        
                    banner_bytes = sock.recv(1024)
                    if banner_bytes:
                        # Extract first line of banner
                        decoded = banner_bytes.decode('utf-8', errors='ignore').split('\r\n')[0].strip()
                        if decoded:
                            banner = decoded[:100] # Limit length
                except:
                    pass
                
                sock.close()
                return {'port': port, 'service': service, 'version': str(banner)}
            sock.close()
        except Exception:
            pass
        return None

    def run(self):
        """Scans the designated ports concurrently and returns open ports with services."""
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in self.ports_to_scan}
            for future in concurrent.futures.as_completed(future_to_port):
                res = future.result()
                if res:
                    open_ports.append(res)
        return open_ports

if __name__ == "__main__":
    scanner = PortScanner("127.0.0.1")
    print(scanner.run())
