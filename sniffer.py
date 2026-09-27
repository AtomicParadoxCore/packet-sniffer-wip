from scapy.all import AsyncSniffer, IP, TCP, UDP
import time
import sys

# Initialization Zone
packet_count = 0
start_time = None  
ip_tracker = {}    
port_tracker = {}  

def packet_callback(packet):
    global packet_count, start_time, ip_tracker, port_tracker
    
    if packet.haslayer(IP):
        if start_time is None:
            start_time = time.time()
            
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        packet_count += 1
        elapsed_time = time.time() - start_time
        
        if src_ip in ip_tracker:
            ip_tracker[src_ip] += 1
        else:
            ip_tracker[src_ip] = 1
        
        if packet_count == 1:
            pps_str = "N/A"  
        elif elapsed_time > 0:
            pps_str = str(int(packet_count / elapsed_time))
        else:
            pps_str = "0"
            
        log_line = ""
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            port_tracker[dst_port] = port_tracker.get(dst_port, 0) + 1
            log_line = f"[{packet_count}] [TCP] {src_ip}:{packet[TCP].sport} -> {dst_ip}:{dst_port} | PPS: {pps_str}\n"
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
            port_tracker[dst_port] = port_tracker.get(dst_port, 0) + 1
            log_line = f"[{packet_count}] [UDP] {src_ip}:{packet[UDP].sport} -> {dst_ip}:{dst_port} | PPS: {pps_str}\n"
            
        if log_line:
            print(log_line.strip())
            with open("network_log.txt", "a") as log_file:
                log_file.write(log_line)
            # CRITICAL ADDITION: Gives the terminal buffer time to print cleanly
            time.sleep(0.01)

def print_summary():
    """Prints the final forensics report to the screen and saves it to network_log.txt"""
    # Create the block of text using an f-string
    summary_text = (
        "\n" + "="*50 + "\n"
        "[!] SNIFFER SESSION TERMINATED BY USER\n"
        + "="*50 + "\n"
        f"Total Packets Captured : {packet_count}\n"
    )
    
    if start_time is not None:
        total_duration = time.time() - start_time
        summary_text += f"Total Session Duration : {total_duration:.2f} seconds\n"
        if total_duration > 0:
            summary_text += f"Average Session Speed  : {int(packet_count / total_duration)} PPS\n"
    else:
        summary_text += "Total Session Duration : 0.00 seconds\n"
        summary_text += "Average Session Speed  : 0 PPS\n"
        
    summary_text += "="*50 + "\n"
    summary_text += "TOP NETWORK TALKERS:\n"
    for ip, count in sorted(ip_tracker.items(), key=lambda x: x[1], reverse=True)[:5]:
        summary_text += f"  - {ip:<15} : {count} packets\n"
        
    summary_text += "-"*50 + "\n"
    summary_text += "MOST TARGETED SERVICES:\n"
    for port, hits in sorted(port_tracker.items(), key=lambda x: x[1], reverse=True)[:5]:
        summary_text += f"  - Port {port:<10} : {hits} hits\n"
    summary_text += "="*50 + "\n"

    # Action 1: Print it out to your Command Prompt window
    print(summary_text)
    
    # Action 2: Append it straight to the bottom of your permanent log file
    with open("network_log.txt", "a") as log_file:
        log_file.write(summary_text)

def main():
    print("[-] Starting Indefinite Asynchronous Sniffer... Press Ctrl+C to stop.")
    
    sniffer = AsyncSniffer(prn=packet_callback, filter="ip", store=0)
    sniffer.start()
    
    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        sniffer.stop()
        print_summary()
        sys.exit(0)

if __name__ == "__main__":
    main()