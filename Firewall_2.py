import json
import sys
import os
import time
import subprocess
from collections import defaultdict, deque
from scapy.all import sniff,IP,TCP
import smtplib
from email.message import EmailMessage

THRESHOLD = 50
maximum_port = 15
scan_detection_window = 10

def send_alert(subject, message):
    sender_email = os.getenv("ALERT_EMAIL")
    receiver_email = os.getenv("ALERT_EMAIL_TO", sender_email)
    app_password = os.getenv("EMAIL_APP_PASSWORD")
    if not app_password:
        print("EMAIL_APP_PASSWORD is not set.")
        return
    email = EmailMessage()
    email["Subject"] = subject
    email["From"] = sender_email
    email["To"] = receiver_email
    email.set_content(message)
    try:
     with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(sender_email, app_password)
        smtp.send_message(email)

        print("Email alert sent successfully")

    except Exception as e:
      print(f"Email alert failed: {e}")

def read_ips(filename) :
    with open(filename, "r") as file:
        ips = [line.strip() for line in file]
        return set(ips)

def port_scan(packet) :
    current_time = time.time()
    time_elapsed = current_time - scan_start_time[0]
    if time_elapsed >= scan_detection_window :
        scan_ports.clear()
        scan_start_time[0] = current_time
    if packet.haslayer(TCP) and packet[TCP].flags == "S" :
        src_ip = packet[IP].src
        destination_port = packet[TCP].dport
        scan_ports[src_ip].add(destination_port)
        if len(scan_ports[src_ip]) >= maximum_port :
            return True
        return False
    
def log_event(event_type,source_ip,severity,message) :
    log_folder = "Logs"
    os.makedirs(log_folder, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    data = {
        "event_type": event_type,
        "source_ip":source_ip,
        "severity" : severity,
        "message" : message,
        "timestamp": timestamp
    }

    log_file = os.path.join(log_folder, f"log_{timestamp}.jsonl")
    with open (log_file , "a") as file :
        json.dump(data,file)
        file.write("\n")


def packet_callback(packet):
       
    # Only process IP packets
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    # Ignore whitelisted IPs
    if src_ip in white_list:
        return

    # Block blacklisted IPs
    if src_ip in blocked_list:
        if src_ip not in blocked_ips:
            subprocess.run([
                "iptables", "-A", "INPUT",
                "-s", src_ip, "-j", "DROP"
            ])

            log_event(
                "blacklisted_ip",
                src_ip,
                "HIGH",
                "Blacklisted IP detected and blocked"
            )

            blocked_ips.add(src_ip)

        return

    # Port scan detection
    if port_scan(packet) and src_ip not in blocked_ips:
        print(f"Port scan detected from {src_ip}")

        subprocess.run([
            "iptables", "-A", "INPUT",
            "-s", src_ip, "-j", "DROP"
        ])

        blocked_ips.add(src_ip)

        log_event(
            "port_scan",
            src_ip,
            "HIGH",
            "Port scan detected and IP blocked"
        )

        send_alert(
            "HIGH: Port Scan Detected",
            f"""Event: Port Scan
Source IP: {src_ip}
Severity: HIGH
Action: IP blocked
"""
        )

        return

    # SYN-rate detection
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        now = time.time()
        timestamps = syn_timestamps[src_ip]

        # Record this SYN
        timestamps.append(now)

        # Keep only SYNs from the last 1 second
        while timestamps and now - timestamps[0] > 1:
            timestamps.popleft()

        packet_rate = len(timestamps)

        print(
            f"DEBUG: {src_ip} -> "
            f"{packet_rate} SYNs in last 1 second"
        )

        if packet_rate > THRESHOLD and src_ip not in blocked_ips:
            print(
                f"Blocking IP: {src_ip}, "
                f"SYN rate: {packet_rate}/s"
            )

            subprocess.run([
                "iptables", "-A", "INPUT",
                "-s", src_ip, "-j", "DROP"
            ])

            blocked_ips.add(src_ip)

            log_event(
                "high_syn_rate",
                src_ip,
                "HIGH",
                f"High SYN packet rate: {packet_rate}/s"
            )

            send_alert(
                "HIGH: SYN Rate Detected",
                f"""Event: High SYN Rate
Source IP: {src_ip}
Packet Rate: {packet_rate} packets/sec
Severity: HIGH
Action: IP blocked
"""
            )

            timestamps.clear()
if __name__ == "__main__" :
    if os.geteuid() != 0 :
        print("This script requires root privileges.")
        sys.exit(1)

    white_list = read_ips("white_list.txt")
    blocked_list = read_ips("blocked_list.txt")
    scan_ports = defaultdict(set)
    scan_start_time = [time.time()]
    syn_timestamps = defaultdict(deque)
    blocked_ips = set()
    print("Monitoring traffic...")
    sniff(
        filter="ip and dst host 192.168.64.2", 
        prn= packet_callback, 
        store = False
    )
