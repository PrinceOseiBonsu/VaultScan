# system_info.py
# Collects basic system information for security audit

import platform
import psutil
import socket
import datetime

def get_system_info():
    # Basic system info
    info = {
        'os': platform.system(),
        'os_version': platform.version(),
        'os_release': platform.release(),
        'hostname': socket.gethostname(),
        'ip_address': socket.gethostbyname(socket.gethostname()),
        'processor': platform.processor(),
        'architecture': platform.architecture()[0],
        'scan_time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # CPU info
    info['cpu_cores'] = psutil.cpu_count(logical=False)
    info['cpu_threads'] = psutil.cpu_count(logical=True)
    info['cpu_usage'] = psutil.cpu_percent(interval=1)

    # Memory info
    memory = psutil.virtual_memory()
    info['total_memory'] = round(memory.total / (1024**3), 2)
    info['used_memory'] = round(memory.used / (1024**3), 2)
    info['memory_percent'] = memory.percent

    # Disk info
    disk = psutil.disk_usage('/')
    info['total_disk'] = round(disk.total / (1024**3), 2)
    info['used_disk'] = round(disk.used / (1024**3), 2)
    info['disk_percent'] = disk.percent

    # Network info
    info['network_interfaces'] = []
    for interface, addresses in psutil.net_if_addrs().items():
        for addr in addresses:
            if str(addr.family) == 'AddressFamily.AF_INET':
                info['network_interfaces'].append({
                    'interface': interface,
                    'ip': addr.address,
                    'netmask': addr.netmask
                })

    return info

if __name__ == "__main__":
    info = get_system_info()
    for key, value in info.items():
        print(f"{key}: {value}")