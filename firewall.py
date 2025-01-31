import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP
from colorama import init
from termcolor import colored

init()
THRESHOLD = 40      # packets per second
print(colored(f"Packet Threshold: {THRESHOLD} packets/minute", 'light_blue'))


def read_ip_file(filename):
    with open(filename, "r") as file:
        ips = [line.strip() for line in file]
    return set(ips)



def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = packet[TCP].payload
        return "GET /scripts/root.exe" in str(payload)
    return False


def log_event(message):
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    timestamp = time.strftime("%d-%m-%Y_%H-%M-%S", time.localtime())
    log_file = os.path.join(log_folder, f"log_{timestamp}.txt")

    with open(log_file, "a") as file:
        file.write(f"{message}\n")


def packet_callback(packet):
    src_ip = packet[IP].src


    # Whitelist check
    if src_ip in whitelist_ips:
        return
    
    # Blacklist check
    if src_ip in blacklist_ips:
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocking blacklisted IP: {src_ip}")
        return
    

    if is_nimda_worm(packet):
        print(f"Blocking Nimda worm source IP: {src_ip}")
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocking Nimda worm source IP: {src_ip}")
        return
    

    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip,count in packet_count.items():
            packet_rate = count / time_interval

            print(f"IP: {ip}, Packet rate: {packet_rate}")        # verbose
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, Packet Rate: {packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                log_event(f"Blocking IP: {ip}, Packet Rate: {packet_rate}")
                blocked_ips.add(ip)            


        packet_count.clear()
        start_time[0] = current_time

def main():
    if os.geteuid() != 0:       # checking root
        print("This script requires root privileges.")
        sys.exit(1)


    # Importing blacklisted and whitelisted IPs
    global whitelist_ips
    whitelist_ips = read_ip_file("whitelist.txt")
    global blacklist_ips
    blacklist_ips = read_ip_file("blacklist.txt")


    global packet_count
    packet_count = defaultdict(int)
    global start_time
    start_time = [time.time()]
    global blocked_ips
    blocked_ips = set()

    print(colored("\nAnalyzing network traffic...", "light_blue"))
    sniff(filter="ip", prn=packet_callback)


if __name__ == "__main__":
    main()