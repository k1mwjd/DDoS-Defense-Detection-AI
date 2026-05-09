from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

from src.utils.config import EXTERNAL_DATASET_DIR, FEATURE_COLUMNS, LABEL_COLUMN, PROCESSED_DATA_DIR


SOURCE_TO_MODEL_COLUMNS = {
    "Destination Port": "destination_port",
    "Protocol": "protocol",
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "total_fwd_packets",
    "Total Backward Packets": "total_backward_packets",
    "Total Length of Fwd Packets": "total_length_fwd_packets",
    "Total Length of Bwd Packets": "total_length_bwd_packets",
    "Flow Bytes/s": "flow_bytes_per_s",
    "Flow Packets/s": "flow_packets_per_s",
    "Fwd Packets/s": "fwd_packets_per_s",
    "Bwd Packets/s": "bwd_packets_per_s",
    "Min Packet Length": "min_packet_length",
    "Max Packet Length": "max_packet_length",
    "Packet Length Mean": "packet_length_mean",
    "Packet Length Std": "packet_length_std",
    "SYN Flag Count": "syn_flag_count",
    "RST Flag Count": "rst_flag_count",
    "ACK Flag Count": "ack_flag_count",
    "Average Packet Size": "average_packet_size",
    "Down/Up Ratio": "down_up_ratio",
}

LABEL_SOURCE_COLUMN = "Label"


def normalize_columns(columns: list[str]) -> list[str]:
    return [str(column).replace("\ufeff", "").strip() for column in columns]


def standardize_chunk(chunk: pd.DataFrame) -> pd.DataFrame:
    df = chunk.copy()
    df.columns = normalize_columns(list(df.columns))
    expected_columns = list(SOURCE_TO_MODEL_COLUMNS.keys()) + [LABEL_SOURCE_COLUMN]
    missing = [column for column in expected_columns if column not in df.columns]
    if missing:
        raise KeyError(f"Missing required source columns: {missing}")

    selected = df[expected_columns].rename(columns=SOURCE_TO_MODEL_COLUMNS)
    label_values = df[LABEL_SOURCE_COLUMN].astype(str).str.strip().str.upper()
    selected[LABEL_COLUMN] = np.where(label_values.isin(["BENIGN", "NORMAL"]), 0, 1)
    selected = selected.drop(columns=[LABEL_SOURCE_COLUMN], errors="ignore")

    for column in FEATURE_COLUMNS:
        selected[column] = pd.to_numeric(selected[column], errors="coerce")

    selected = selected.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return selected


def collect_csv_files(dataset_dir: Path) -> list[Path]:
    return sorted(
        path
        for path in dataset_dir.rglob("*.csv")
        if path.is_file() and not path.name.startswith(".~lock.")
    )


def sample_balanced_from_file(
    csv_path: Path,
    max_benign_rows: int,
    max_attack_rows: int,
    chunk_size: int,
) -> tuple[pd.DataFrame, dict[str, int]]:
    benign_frames: list[pd.DataFrame] = []
    attack_frames: list[pd.DataFrame] = []
    benign_count = 0
    attack_count = 0

    for chunk in pd.read_csv(csv_path, chunksize=chunk_size, low_memory=False):
        standardized = standardize_chunk(chunk)

        if benign_count < max_benign_rows:
            benign_chunk = standardized[standardized[LABEL_COLUMN] == 0]
            if not benign_chunk.empty:
                remaining = max_benign_rows - benign_count
                benign_take = benign_chunk.head(remaining)
                benign_frames.append(benign_take)
                benign_count += len(benign_take)

        if attack_count < max_attack_rows:
            attack_chunk = standardized[standardized[LABEL_COLUMN] == 1]
            if not attack_chunk.empty:
                remaining = max_attack_rows - attack_count
                attack_take = attack_chunk.head(remaining)
                attack_frames.append(attack_take)
                attack_count += len(attack_take)

        if benign_count >= max_benign_rows and attack_count >= max_attack_rows:
            break

    frames = benign_frames + attack_frames
    if frames:
        sampled = pd.concat(frames, ignore_index=True)
    else:
        sampled = pd.DataFrame(columns=FEATURE_COLUMNS + [LABEL_COLUMN])

    metadata = {
        "benign_rows": benign_count,
        "attack_rows": attack_count,
    }
    return sampled, metadata


def build_split_dataset(
    input_dir: Path,
    output_csv: Path,
    metadata_path: Path,
    max_benign_rows_per_file: int,
    max_attack_rows_per_file: int,
    chunk_size: int,
) -> None:
    csv_files = collect_csv_files(input_dir)
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found under {input_dir}")

    frames: list[pd.DataFrame] = []
    file_stats: dict[str, dict[str, int]] = {}
    total_counter: Counter[int] = Counter()

    for csv_file in csv_files:
        print(f"Sampling: {csv_file.name}")
        sampled_df, sampled_stats = sample_balanced_from_file(
            csv_path=csv_file,
            max_benign_rows=max_benign_rows_per_file,
            max_attack_rows=max_attack_rows_per_file,
            chunk_size=chunk_size,
        )
        if sampled_df.empty:
            continue

        frames.append(sampled_df)
        total_counter.update(sampled_df[LABEL_COLUMN].astype(int).tolist())
        file_stats[csv_file.name] = sampled_stats

    if not frames:
        raise ValueError(f"No rows were sampled from {input_dir}")

    combined = pd.concat(frames, ignore_index=True)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)

    combined.to_csv(output_csv, index=False)
    metadata = {
        "input_dir": str(input_dir),
        "output_csv": str(output_csv),
        "feature_columns": FEATURE_COLUMNS,
        "label_column": LABEL_COLUMN,
        "row_count": int(len(combined)),
        "label_distribution": {str(key): int(value) for key, value in sorted(total_counter.items())},
        "file_stats": file_stats,
        "max_benign_rows_per_file": max_benign_rows_per_file,
        "max_attack_rows_per_file": max_attack_rows_per_file,
        "chunk_size": chunk_size,
    }
    with open(metadata_path, "w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=2, ensure_ascii=False)

    print(f"Saved dataset to: {output_csv}")
    print(f"Saved metadata to: {metadata_path}")
    print(f"Rows: {len(combined)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare a CSV-based DDoS dataset from CIC CSV files.")
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=EXTERNAL_DATASET_DIR / "01-12",
        help="Directory containing CIC CSV files.",
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=PROCESSED_DATA_DIR / "train_dataset.csv",
        help="Output dataset path.",
    )
    parser.add_argument(
        "--metadata-output",
        type=Path,
        default=PROCESSED_DATA_DIR / "train_dataset_metadata.json",
        help="Metadata output path.",
    )
    parser.add_argument("--max-benign-rows-per-file", type=int, default=1000, help="Maximum benign rows to keep per file.")
    parser.add_argument("--max-attack-rows-per-file", type=int, default=4000, help="Maximum attack rows to keep per file.")
    parser.add_argument("--chunk-size", type=int, default=50000, help="Chunk size for large CSV processing.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    build_split_dataset(
        input_dir=args.input_dir,
        output_csv=args.output_csv,
        metadata_path=args.metadata_output,
        max_benign_rows_per_file=args.max_benign_rows_per_file,
        max_attack_rows_per_file=args.max_attack_rows_per_file,
        chunk_size=args.chunk_size,
    )
