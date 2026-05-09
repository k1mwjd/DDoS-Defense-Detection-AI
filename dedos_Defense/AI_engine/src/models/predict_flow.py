from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd

from src.utils.config import FEATURE_COLUMNS


def predict_csv(model_path: Path, input_csv: Path, output_csv: Path | None = None) -> pd.DataFrame:
    model = joblib.load(model_path)
    df = pd.read_csv(input_csv)

    missing_columns = [column for column in FEATURE_COLUMNS if column not in df.columns]
    if missing_columns:
        raise KeyError(f"Missing required feature columns: {missing_columns}")

    predictions = model.predict(df[FEATURE_COLUMNS])
    prediction_probs = model.predict_proba(df[FEATURE_COLUMNS])[:, 1]

    result = df.copy()
    result["prediction"] = predictions
    result["attack_probability"] = prediction_probs

    if output_csv is not None:
        output_csv.parent.mkdir(parents=True, exist_ok=True)
        result.to_csv(output_csv, index=False)
        print(f"Saved predictions to: {output_csv}")

    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run inference on extracted DDoS feature CSVs.")
    parser.add_argument("--model-path", type=Path, required=True, help="Path to trained model.")
    parser.add_argument("--input-csv", type=Path, required=True, help="Feature CSV to predict.")
    parser.add_argument("--output-csv", type=Path, default=None, help="Optional path to save predictions.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    predictions = predict_csv(
        model_path=args.model_path,
        input_csv=args.input_csv,
        output_csv=args.output_csv,
    )
    print(predictions.head())
