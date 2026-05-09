from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
REALTIME_LOG_DIR = DATA_DIR / "realtime_logs"
MODEL_DIR = PROJECT_ROOT / "models"
EXTERNAL_DATASET_DIR = PROJECT_ROOT.parent / "data" / "csv"

WINDOW_SECONDS = 1.0

FEATURE_COLUMNS = [
    "destination_port",
    "protocol",
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "total_length_fwd_packets",
    "total_length_bwd_packets",
    "flow_bytes_per_s",
    "flow_packets_per_s",
    "fwd_packets_per_s",
    "bwd_packets_per_s",
    "min_packet_length",
    "max_packet_length",
    "packet_length_mean",
    "packet_length_std",
    "syn_flag_count",
    "rst_flag_count",
    "ack_flag_count",
    "average_packet_size",
    "down_up_ratio",
]

LABEL_COLUMN = "label"
