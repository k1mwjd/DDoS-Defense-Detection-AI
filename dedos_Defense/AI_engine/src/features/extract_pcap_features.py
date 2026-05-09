from __future__ import annotations

import argparse
import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean, pstdev

import pandas as pd
from scapy.all import ICMP, IP, IPv6, PcapReader, TCP, UDP  # type: ignore

from src.utils.config import FEATURE_COLUMNS, LABEL_COLUMN, WINDOW_SECONDS


@dataclass
class WindowAccumulator:
    packet_count: int = 0
    byte_count: int = 0
    src_ips: set[str] = field(default_factory=set)
    dst_ips: set[str] = field(default_factory=set)
    src_ports: set[int] = field(default_factory=set)
    dst_ports: set[int] = field(default_factory=set)
    protocol_counts: Counter[str] = field(default_factory=Counter)
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    packet_lengths: list[int] = field(default_factory=list)
    timestamps: list[float] = field(default_factory=list)

    def update(self, packet_time: float, packet_length: int, src_ip: str, dst_ip: str, src_port: int | None, dst_port: int | None, protocol: str, tcp_flags: int | None) -> None:
        self.packet_count += 1
        self.byte_count += packet_length
        self.src_ips.add(src_ip)
        self.dst_ips.add(dst_ip)
        if src_port is not None:
            self.src_ports.add(src_port)
        if dst_port is not None:
            self.dst_ports.add(dst_port)
        self.protocol_counts[protocol] += 1
        self.packet_lengths.append(packet_length)
        self.timestamps.append(packet_time)

        if tcp_flags is not None:
            if tcp_flags & 0x02:
                self.syn_count += 1
            if tcp_flags & 0x10:
                self.ack_count += 1
            if tcp_flags & 0x04:
                self.rst_count += 1

    def to_feature_row(self, window_start: float, label: int, source_file: str) -> dict[str, object]:
        tcp_count = self.protocol_counts.get("TCP", 0)
        udp_count = self.protocol_counts.get("UDP", 0)
        icmp_count = self.protocol_counts.get("ICMP", 0)

        if self.packet_count <= 1:
            mean_iat = 0.0
        else:
            ordered = sorted(self.timestamps)
            gaps = [ordered[idx] - ordered[idx - 1] for idx in range(1, len(ordered))]
            mean_iat = mean(gaps) if gaps else 0.0

        row = {
            "window_start": window_start,
            "source_file": source_file,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "unique_src_ip_count": len(self.src_ips),
            "unique_dst_ip_count": len(self.dst_ips),
            "unique_src_port_count": len(self.src_ports),
            "unique_dst_port_count": len(self.dst_ports),
            "tcp_ratio": tcp_count / self.packet_count if self.packet_count else 0.0,
            "udp_ratio": udp_count / self.packet_count if self.packet_count else 0.0,
            "icmp_ratio": icmp_count / self.packet_count if self.packet_count else 0.0,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "rst_count": self.rst_count,
            "syn_ack_ratio": self.syn_count / self.ack_count if self.ack_count else float(self.syn_count),
            "mean_packet_length": mean(self.packet_lengths) if self.packet_lengths else 0.0,
            "std_packet_length": pstdev(self.packet_lengths) if len(self.packet_lengths) > 1 else 0.0,
            "mean_inter_arrival_time": mean_iat,
            LABEL_COLUMN: label,
        }
        return row


def resolve_ip_layer(packet):
    if IP in packet:
        return packet[IP]
    if IPv6 in packet:
        return packet[IPv6]
    return None


def protocol_name(packet) -> str:
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if ICMP in packet:
        return "ICMP"
    return "OTHER"


def packet_ports(packet) -> tuple[int | None, int | None]:
    if TCP in packet:
        return int(packet[TCP].sport), int(packet[TCP].dport)
    if UDP in packet:
        return int(packet[UDP].sport), int(packet[UDP].dport)
    return None, None


def packet_tcp_flags(packet) -> int | None:
    if TCP not in packet:
        return None
    flags = packet[TCP].flags
    return int(flags)


def extract_features_from_pcap(pcap_path: Path, label: int, window_seconds: float = WINDOW_SECONDS) -> pd.DataFrame:
    windows: dict[int, WindowAccumulator] = {}

    with PcapReader(str(pcap_path)) as reader:
        for packet in reader:
            ip_layer = resolve_ip_layer(packet)
            if ip_layer is None:
                continue

            packet_time = float(packet.time)
            if math.isnan(packet_time):
                continue

            window_index = int(packet_time // window_seconds)
            window_start = window_index * window_seconds

            accumulator = windows.setdefault(window_index, WindowAccumulator())
            src_port, dst_port = packet_ports(packet)
            accumulator.update(
                packet_time=packet_time,
                packet_length=len(packet),
                src_ip=str(ip_layer.src),
                dst_ip=str(ip_layer.dst),
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol_name(packet),
                tcp_flags=packet_tcp_flags(packet),
            )

    rows = [
        accumulator.to_feature_row(
            window_start=window_index * window_seconds,
            label=label,
            source_file=pcap_path.name,
        )
        for window_index, accumulator in sorted(windows.items())
        if accumulator.packet_count > 0
    ]
    return pd.DataFrame(rows)


def collect_pcaps(input_path: Path) -> list[Path]:
    if input_path.is_file():
        return [input_path]
    return sorted(
        path
        for path in input_path.rglob("*")
        if path.is_file() and path.suffix.lower() in {".pcap", ".pcapng", ".cap"}
    )


def build_dataset(input_path: Path, output_csv: Path, label: int, window_seconds: float = WINDOW_SECONDS) -> None:
    pcap_files = collect_pcaps(input_path)
    if not pcap_files:
        raise FileNotFoundError(f"No PCAP files found under {input_path}")

    frames: list[pd.DataFrame] = []
    for pcap_file in pcap_files:
        print(f"Extracting features from: {pcap_file}")
        df = extract_features_from_pcap(
            pcap_path=pcap_file,
            label=label,
            window_seconds=window_seconds,
        )
        if not df.empty:
            frames.append(df)

    if not frames:
        raise ValueError("PCAP files were read, but no feature rows were produced.")

    combined = pd.concat(frames, ignore_index=True)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(output_csv, index=False)
    print(f"Saved feature dataset to: {output_csv}")
    print(f"Rows: {len(combined)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract window-based DDoS features from PCAP files.")
    parser.add_argument("--input", type=Path, required=True, help="PCAP file or directory containing PCAP files.")
    parser.add_argument("--output-csv", type=Path, required=True, help="Path to save the extracted feature CSV.")
    parser.add_argument("--label", type=int, choices=[0, 1], required=True, help="0 for benign, 1 for attack.")
    parser.add_argument("--window-seconds", type=float, default=WINDOW_SECONDS, help="Aggregation window size in seconds.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    build_dataset(
        input_path=args.input,
        output_csv=args.output_csv,
        label=args.label,
        window_seconds=args.window_seconds,
    )
