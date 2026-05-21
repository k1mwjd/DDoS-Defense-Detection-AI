from __future__ import annotations

import os
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parent
AI_ENGINE_ROOT = PROJECT_ROOT / "AI_engine"
MODEL_DIR = AI_ENGINE_ROOT / "models"
RUNTIME_LOG_DIR = BACKEND_ROOT / "runtime_logs"

DEFAULT_MODEL_PATH = Path(os.getenv("AI_DDOS_MODEL_PATH", str(MODEL_DIR / "random_forest_medium.joblib")))
DEFAULT_DEFENSE_THRESHOLD = float(os.getenv("AI_DDOS_DEFENSE_THRESHOLD", "70"))
DEFAULT_BLOCK_SECONDS = int(os.getenv("AI_DDOS_BLOCK_SECONDS", "600"))
ENABLE_WINDOWS_FIREWALL = os.getenv("AI_DDOS_ENABLE_WINDOWS_FIREWALL", "false").lower() == "true"

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

RUNTIME_LOG_DIR.mkdir(parents=True, exist_ok=True)
