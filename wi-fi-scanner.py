import scapy.all as scapy
import socket

def get_local_ip():
    """
    Get the local IP address of the device.
    """
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except socket.error as e:
        print(f"[ERROR] Unable to get local IP: {e}")
        return None

def scan_network(ip_range):
    """
    Scan the network and return a list of connected devices.
    """
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list, _ = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)

        devices = []
        for element in answered_list:
            device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            devices.append(device)
        
        return devices
    except Exception as e:
        print(f"[ERROR] Network scan failed: {e}")
        return []

def main():
    """
    Main function that executes the WiFi scanner.
    """
    local_ip = get_local_ip()
    if not local_ip:
        print("[ERROR] Could not determine local IP. Exiting.")
        return

    # Determine the network range (assumes a /24 subnet)
    network_range = ".".join(local_ip.split(".")[:-1]) + ".1/24"

    print(f"\n🔍 Scanning network: {network_range}\n")
    devices = scan_network(network_range)

    print("📡 Connected Devices:")
    print("-" * 50)
    print(f"{'IP Address':<20} {'MAC Address':<20}")
    print("-" * 50)
    for device in devices:
        print(f"{device['ip']:<20} {device['mac']:<20}")
    print("-" * 50)
    print(f"✅ {len(devices)} devices found.")

if __name__ == "__main__":
    main()
