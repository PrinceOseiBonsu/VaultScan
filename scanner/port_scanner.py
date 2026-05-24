# port_scanner.py
# Scans open ports and identifies potential security risks

import socket
import concurrent.futures
import datetime

# Common ports and their services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alt",
    8443: "HTTPS Alt",
    27017: "MongoDB"
}

# Ports that are risky if open
RISKY_PORTS = {
    21: "FTP transmits data in plain text",
    23: "Telnet is unencrypted and highly insecure",
    135: "RPC can be exploited for remote attacks",
    139: "NetBIOS exposes network information",
    445: "SMB vulnerabilities like EternalBlue",
    3389: "RDP is a common ransomware entry point",
    5900: "VNC can expose your desktop remotely",
    6379: "Redis often misconfigured with no auth",
    27017: "MongoDB often misconfigured with no auth"
}

def scan_port(host, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port, result == 0
    except:
        return port, False

def scan_ports(host="127.0.0.1", ports=None):
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    print(f"Scanning {host}...")
    open_ports = []
    risky_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                service = COMMON_PORTS.get(port, "Unknown")
                port_info = {
                    'port': port,
                    'service': service,
                    'status': 'open',
                    'risk': port in RISKY_PORTS,
                    'risk_reason': RISKY_PORTS.get(port, None)
                }
                open_ports.append(port_info)
                if port in RISKY_PORTS:
                    risky_ports.append(port_info)

    open_ports.sort(key=lambda x: x['port'])

    return {
        'host': host,
        'open_ports': open_ports,
        'risky_ports': risky_ports,
        'total_open': len(open_ports),
        'total_risky': len(risky_ports),
        'scan_time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

if __name__ == "__main__":
    results = scan_ports("127.0.0.1")
    print(f"\nOpen ports: {results['total_open']}")
    print(f"Risky ports: {results['total_risky']}")
    for port in results['open_ports']:
        risk = "⚠️ RISKY" if port['risk'] else "✅ OK"
        print(f"Port {port['port']} ({port['service']}) — {risk}")