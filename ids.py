from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict, deque, Counter
from datetime import datetime
import threading
import time
import csv
import logging
import os
import math


class MiniIDS:
    def __init__(
        self,
        time_window,
        port_threshold,
        syn_threshold,
        icmp_threshold,
        log_file,
        csv_file,
        output_callback=None,
        alert_callback=None,
        entropy_threshold=2.0,
        entropy_min_ports=5
    ):
        self.time_window = time_window
        self.port_threshold = port_threshold
        self.syn_threshold = syn_threshold
        self.icmp_threshold = icmp_threshold
        self.entropy_threshold = entropy_threshold
        self.entropy_min_ports = entropy_min_ports

        self.log_file = log_file
        self.csv_file = csv_file

        self.output_callback = output_callback
        self.alert_callback = alert_callback

        self.running = True
        self.packet_count = 0
        self.alert_count = 0

        self.syn_records = defaultdict(lambda: deque())
        self.icmp_records = defaultdict(lambda: deque())
        self.udp_records = defaultdict(lambda: deque())

        self.suspicious_ips = set()
        self.alert_history = []

        self.protocol_stats = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "OTHER": 0
        }

        self.attack_stats = {
            "Port Scan": 0,
            "SYN Flood": 0,
            "ICMP Flood": 0,
            "Entropy Port Scan": 0
        }

        self.lock = threading.Lock()

        self.setup_logger()
        self.prepare_csv()

    def setup_logger(self):
        self.logger = logging.getLogger(f"MiniIDS_{id(self)}")
        self.logger.setLevel(logging.WARNING)
        self.logger.propagate = False

        if not self.logger.handlers:
            file_handler = logging.FileHandler(self.log_file)
            formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s"
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def write_output(self, message):
        print(message)

        if self.output_callback:
            self.output_callback(message)

    def prepare_csv(self):
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, mode="w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow([
                    "timestamp",
                    "src_ip",
                    "dst_ip",
                    "protocol",
                    "src_port",
                    "dst_port",
                    "flags",
                    "packet_length"
                ])

    def log_packet_to_csv(
        self,
        timestamp,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        flags,
        packet_length
    ):
        with open(self.csv_file, mode="a", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow([
                timestamp,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                flags,
                packet_length
            ])

    def alert(self, message, attack_type=None):
        with self.lock:
            self.alert_count += 1

            if attack_type and attack_type in self.attack_stats:
                self.attack_stats[attack_type] += 1

        full_message = f"[ALERT] {message}"

        self.alert_history.append(full_message)

        self.write_output("")
        self.write_output(full_message)
        self.write_output("")

        self.logger.warning(message)

        if self.alert_callback:
            self.alert_callback(full_message)

    def clean_old_records(self, records, ip, current_time):
        """
        Sliding Window Algorithm:
        Remove old packet records that are outside the selected time window.
        """
        while records[ip] and current_time - records[ip][0][0] > self.time_window:
            records[ip].popleft()

    def calculate_entropy(self, ports):
        """
        Entropy-Based Anomaly Detection:
        This function measures the randomness of destination ports.

        High entropy means the source IP is trying many different ports,
        which can indicate a port scan attack.
        """
        if not ports:
            return 0.0

        total = len(ports)
        counts = Counter(ports)

        entropy = 0.0

        for count in counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability)

        return entropy

    def preprocess_packet(self, packet):
        """
        Pre-processing stage:
        1. Check if IDS is running.
        2. Filter non-IP packets.
        3. Extract important features from the packet.
        """

        if not self.running:
            return None

        if not packet.haslayer(IP):
            return None

        current_time = time.time()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_length = len(packet)

        packet_data = {
            "current_time": current_time,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "packet_length": packet_length
        }

        return packet_data

    def handle_tcp_packet(self, packet, src_ip, dst_ip, timestamp, packet_length, current_time):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = str(packet[TCP].flags)
        protocol = "TCP"

        with self.lock:
            self.protocol_stats["TCP"] += 1

        self.log_packet_to_csv(
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            flags,
            packet_length
        )

        self.write_output(
            f"[TCP] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flags={flags}"
        )

        if flags == "S":
            self.syn_records[src_ip].append((current_time, dst_port))
            self.clean_old_records(self.syn_records, src_ip, current_time)

            destination_ports = [port for _, port in self.syn_records[src_ip]]
            unique_ports = set(destination_ports)
            syn_count = len(self.syn_records[src_ip])
            entropy_score = self.calculate_entropy(destination_ports)

            if len(unique_ports) >= self.entropy_min_ports and entropy_score >= self.entropy_threshold:
                self.suspicious_ips.add(src_ip)
                self.alert(
                    f"Entropy-Based Port Scan from {src_ip} "
                    f"(Entropy={entropy_score:.2f}, Unique Ports={len(unique_ports)}, "
                    f"Window={self.time_window} seconds)",
                    attack_type="Entropy Port Scan"
                )
                self.syn_records[src_ip].clear()

            elif len(unique_ports) >= self.port_threshold:
                self.suspicious_ips.add(src_ip)
                self.alert(
                    f"Possible Port Scan from {src_ip} "
                    f"({len(unique_ports)} different ports in {self.time_window} seconds)",
                    attack_type="Port Scan"
                )
                self.syn_records[src_ip].clear()

            elif syn_count >= self.syn_threshold:
                self.suspicious_ips.add(src_ip)
                self.alert(
                    f"Possible SYN Flood from {src_ip} "
                    f"({syn_count} SYN packets in {self.time_window} seconds)",
                    attack_type="SYN Flood"
                )
                self.syn_records[src_ip].clear()

    def handle_udp_packet(self, packet, src_ip, dst_ip, timestamp, packet_length, current_time):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        protocol = "UDP"
        flags = ""

        with self.lock:
            self.protocol_stats["UDP"] += 1

        self.log_packet_to_csv(
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            flags,
            packet_length
        )

        self.write_output(f"[UDP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        self.udp_records[src_ip].append((current_time, dst_port))
        self.clean_old_records(self.udp_records, src_ip, current_time)

    def handle_icmp_packet(self, packet, src_ip, dst_ip, timestamp, packet_length, current_time):
        protocol = "ICMP"
        src_port = ""
        dst_port = ""
        flags = ""

        with self.lock:
            self.protocol_stats["ICMP"] += 1

        self.log_packet_to_csv(
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            flags,
            packet_length
        )

        self.write_output(f"[ICMP] {src_ip} -> {dst_ip}")

        self.icmp_records[src_ip].append((current_time, "ICMP"))
        self.clean_old_records(self.icmp_records, src_ip, current_time)

        icmp_count = len(self.icmp_records[src_ip])

        if icmp_count >= self.icmp_threshold:
            self.suspicious_ips.add(src_ip)
            self.alert(
                f"Possible ICMP Flood from {src_ip} "
                f"({icmp_count} ICMP packets in {self.time_window} seconds)",
                attack_type="ICMP Flood"
            )
            self.icmp_records[src_ip].clear()

    def handle_other_packet(self, src_ip, dst_ip, timestamp, packet_length):
        protocol = "OTHER"
        src_port = ""
        dst_port = ""
        flags = ""

        with self.lock:
            self.protocol_stats["OTHER"] += 1

        self.log_packet_to_csv(
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            flags,
            packet_length
        )

        self.write_output(f"[OTHER] {src_ip} -> {dst_ip}")

    def process_packet(self, packet):
        packet_data = self.preprocess_packet(packet)

        if packet_data is None:
            return

        with self.lock:
            self.packet_count += 1

        current_time = packet_data["current_time"]
        timestamp = packet_data["timestamp"]
        src_ip = packet_data["src_ip"]
        dst_ip = packet_data["dst_ip"]
        packet_length = packet_data["packet_length"]

        try:
            if packet.haslayer(TCP):
                self.handle_tcp_packet(
                    packet,
                    src_ip,
                    dst_ip,
                    timestamp,
                    packet_length,
                    current_time
                )

            elif packet.haslayer(UDP):
                self.handle_udp_packet(
                    packet,
                    src_ip,
                    dst_ip,
                    timestamp,
                    packet_length,
                    current_time
                )

            elif packet.haslayer(ICMP):
                self.handle_icmp_packet(
                    packet,
                    src_ip,
                    dst_ip,
                    timestamp,
                    packet_length,
                    current_time
                )

            else:
                self.handle_other_packet(
                    src_ip,
                    dst_ip,
                    timestamp,
                    packet_length
                )

        except Exception as e:
            self.write_output(f"[ERROR while processing packet] {e}")

    def sniff_packets(self):
        self.running = True

        try:
            while self.running:
                sniff(
                    prn=self.process_packet,
                    store=False,
                    timeout=1
                )

        except PermissionError:
            self.write_output(
                "[ERROR] Permission denied. Please run the program as Administrator."
            )

        except Exception as e:
            self.write_output(f"[ERROR] {e}")

    def show_stats(self):
        while self.running:
            time.sleep(10)

            with self.lock:
                self.write_output("")
                self.write_output("=" * 60)
                self.write_output("LIVE STATISTICS")
                self.write_output("=" * 60)
                self.write_output(f"Total Packets Captured : {self.packet_count}")
                self.write_output(f"Total Alerts           : {self.alert_count}")
                self.write_output(f"TCP Packets            : {self.protocol_stats['TCP']}")
                self.write_output(f"UDP Packets            : {self.protocol_stats['UDP']}")
                self.write_output(f"ICMP Packets           : {self.protocol_stats['ICMP']}")
                self.write_output(f"Other Packets          : {self.protocol_stats['OTHER']}")
                self.write_output(f"Suspicious IPs         : {len(self.suspicious_ips)}")

                if self.suspicious_ips:
                    self.write_output("List of suspicious IPs:")
                    for ip in self.suspicious_ips:
                        self.write_output(f" - {ip}")
                else:
                    self.write_output("No suspicious IPs detected yet.")

                self.write_output("=" * 60)
                self.write_output("")

    def stop(self):
        self.running = False

    def get_stats(self):
        with self.lock:
            return {
                "packet_count": self.packet_count,
                "alert_count": self.alert_count,
                "protocol_stats": dict(self.protocol_stats),
                "attack_stats": dict(self.attack_stats),
                "suspicious_ips": list(self.suspicious_ips),
                "alert_history": list(self.alert_history)
            }

    def generate_report(self):
        self.write_output("")
        self.write_output("=" * 60)
        self.write_output("FINAL REPORT")
        self.write_output("=" * 60)
        self.write_output(f"Packets Captured : {self.packet_count}")
        self.write_output(f"Alerts Generated : {self.alert_count}")
        self.write_output(f"TCP Packets      : {self.protocol_stats['TCP']}")
        self.write_output(f"UDP Packets      : {self.protocol_stats['UDP']}")
        self.write_output(f"ICMP Packets     : {self.protocol_stats['ICMP']}")
        self.write_output(f"Other Packets    : {self.protocol_stats['OTHER']}")
        self.write_output(f"Suspicious IPs   : {len(self.suspicious_ips)}")

        if self.suspicious_ips:
            self.write_output("")
            self.write_output("List of suspicious IPs:")
            for ip in self.suspicious_ips:
                self.write_output(f" - {ip}")
        else:
            self.write_output("")
            self.write_output("No suspicious IPs detected.")

        self.write_output("")
        self.write_output(f"Log file saved as : {self.log_file}")
        self.write_output(f"CSV file saved as : {self.csv_file}")
        self.write_output("=" * 60)


if __name__ == "__main__":
    print("This file contains the core IDS class.")
    print("To open the graphical interface, run: py gui_ids.py")