from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
import json
import math
from pathlib import Path
from statistics import mean, pstdev
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import pandas as pd
from scapy.all import ICMP, IP, IPv6, PcapReader, TCP, UDP, sniff  # type: ignore

from app.config import FEATURE_COLUMNS, RUNTIME_LOG_DIR


FlowTuple = Tuple[str, int, str, int, int]


@dataclass
class PacketView:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    length: int
    tcp_flags: int


@dataclass
class FlowAccumulator:
    flow_id: str
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: int
    start_time: float
    end_time: float
    total_fwd_packets: int = 0
    total_backward_packets: int = 0
    total_length_fwd_packets: int = 0
    total_length_bwd_packets: int = 0
    lengths: List[int] = field(default_factory=list)
    syn_flag_count: int = 0
    rst_flag_count: int = 0
    ack_flag_count: int = 0

    def update(self, packet: PacketView, is_forward: bool) -> None:
        self.end_time = max(self.end_time, packet.timestamp)
        self.lengths.append(packet.length)

        if is_forward:
            self.total_fwd_packets += 1
            self.total_length_fwd_packets += packet.length
        else:
            self.total_backward_packets += 1
            self.total_length_bwd_packets += packet.length

        if packet.tcp_flags & 0x02:
            self.syn_flag_count += 1
        if packet.tcp_flags & 0x04:
            self.rst_flag_count += 1
        if packet.tcp_flags & 0x10:
            self.ack_flag_count += 1

    def to_record(self) -> Dict[str, Any]:
        duration_seconds = max(self.end_time - self.start_time, 0.0)
        safe_duration = duration_seconds if duration_seconds > 0 else 1e-6
        total_packets = self.total_fwd_packets + self.total_backward_packets
        total_bytes = self.total_length_fwd_packets + self.total_length_bwd_packets

        return {
            "flow_id": self.flow_id,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "flow_duration": round(duration_seconds * 1_000_000, 3),
            "total_fwd_packets": self.total_fwd_packets,
            "total_backward_packets": self.total_backward_packets,
            "total_length_fwd_packets": self.total_length_fwd_packets,
            "total_length_bwd_packets": self.total_length_bwd_packets,
            "flow_bytes_per_s": round(total_bytes / safe_duration, 6),
            "flow_packets_per_s": round(total_packets / safe_duration, 6),
            "fwd_packets_per_s": round(self.total_fwd_packets / safe_duration, 6),
            "bwd_packets_per_s": round(self.total_backward_packets / safe_duration, 6),
            "min_packet_length": min(self.lengths) if self.lengths else 0,
            "max_packet_length": max(self.lengths) if self.lengths else 0,
            "packet_length_mean": round(mean(self.lengths), 6) if self.lengths else 0.0,
            "packet_length_std": round(pstdev(self.lengths), 6) if len(self.lengths) > 1 else 0.0,
            "syn_flag_count": self.syn_flag_count,
            "rst_flag_count": self.rst_flag_count,
            "ack_flag_count": self.ack_flag_count,
            "average_packet_size": round(total_bytes / total_packets, 6) if total_packets else 0.0,
            "down_up_ratio": round(self.total_backward_packets / max(self.total_fwd_packets, 1), 6),
        }


def _protocol_number(packet: Any) -> Optional[int]:
    if TCP in packet:
        return 6
    if UDP in packet:
        return 17
    if ICMP in packet:
        return 1
    if IP in packet:
        return int(packet[IP].proto)
    if IPv6 in packet:
        return int(packet[IPv6].nh)
    return None


def _extract_packet_view(packet: Any) -> Optional[PacketView]:
    ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
    if ip_layer is None:
        return None

    protocol = _protocol_number(packet)
    if protocol is None:
        return None

    src_port = 0
    dst_port = 0
    tcp_flags = 0

    if TCP in packet:
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
        tcp_flags = int(packet[TCP].flags)
    elif UDP in packet:
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    try:
        timestamp = float(packet.time)
    except Exception:
        return None
    if math.isnan(timestamp):
        return None

    return PacketView(
        timestamp=timestamp,
        src_ip=str(ip_layer.src),
        dst_ip=str(ip_layer.dst),
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=len(packet),
        tcp_flags=tcp_flags,
    )


def _normalize_flow_keys(packet: PacketView) -> Tuple[FlowTuple, FlowTuple]:
    forward = (packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port, packet.protocol)
    reverse = (packet.dst_ip, packet.dst_port, packet.src_ip, packet.src_port, packet.protocol)
    return forward, reverse


def build_flow_dataframe_from_packets(packets: List[Any]) -> pd.DataFrame:
    flows: Dict[FlowTuple, FlowAccumulator] = {}
    counter = 0

    for raw_packet in packets:
        packet = _extract_packet_view(raw_packet)
        if packet is None:
            continue

        forward_key, reverse_key = _normalize_flow_keys(packet)

        if forward_key in flows:
            accumulator = flows[forward_key]
            is_forward = True
        elif reverse_key in flows:
            accumulator = flows[reverse_key]
            is_forward = False
        else:
            counter += 1
            accumulator = FlowAccumulator(
                flow_id=f"flow-{counter:06d}",
                source_ip=packet.src_ip,
                destination_ip=packet.dst_ip,
                destination_port=packet.dst_port,
                protocol=packet.protocol,
                start_time=packet.timestamp,
                end_time=packet.timestamp,
            )
            flows[forward_key] = accumulator
            is_forward = True

        accumulator.update(packet, is_forward)

    records = [accumulator.to_record() for accumulator in flows.values()]
    if not records:
        columns = ["flow_id", "source_ip", "destination_ip", *FEATURE_COLUMNS]
        return pd.DataFrame(columns=columns)
    return pd.DataFrame.from_records(records)


def analyze_pcap_file(pcap_path: Path, packet_limit: Optional[int] = None) -> pd.DataFrame:
    packets: List[Any] = []
    with PcapReader(str(pcap_path)) as reader:
        for index, packet in enumerate(reader):
            packets.append(packet)
            if packet_limit and index + 1 >= packet_limit:
                break
    return build_flow_dataframe_from_packets(packets)


def analyze_live_interface(interface: str, duration_seconds: int, packet_limit: Optional[int] = None) -> pd.DataFrame:
    sniff_kwargs: Dict[str, Any] = {
        "iface": interface,
        "timeout": duration_seconds,
        "store": True,
    }
    if packet_limit:
        sniff_kwargs["count"] = packet_limit

    packets = sniff(**sniff_kwargs)
    return build_flow_dataframe_from_packets(list(packets))


def write_analysis_logs(df: pd.DataFrame, prefix: str) -> Tuple[str, str]:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = RUNTIME_LOG_DIR / f"{prefix}_{timestamp}.csv"
    json_path = RUNTIME_LOG_DIR / f"{prefix}_{timestamp}.json"

    df.to_csv(csv_path, index=False, encoding="utf-8-sig")
    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(df.to_dict(orient="records"), handle, ensure_ascii=False, indent=2)

    return str(csv_path), str(json_path)
