from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from src.utils.config import FEATURE_COLUMNS, LABEL_COLUMN


def load_feature_csvs(csv_paths: list[Path]) -> pd.DataFrame:
    frames = [pd.read_csv(path) for path in csv_paths]
    if not frames:
        raise ValueError("No feature CSV files were provided.")
    combined = pd.concat(frames, ignore_index=True)
    return combined


def validate_dataset(df: pd.DataFrame) -> None:
    missing_columns = [column for column in FEATURE_COLUMNS + [LABEL_COLUMN] if column not in df.columns]
    if missing_columns:
        raise KeyError(f"Missing required columns: {missing_columns}")


def train_model(
    input_csvs: list[Path] | None,
    model_output: Path,
    metadata_output: Path,
    train_csv: Path | None = None,
    test_csv: Path | None = None,
    test_size: float = 0.2,
    random_state: int = 42,
    n_estimators: int = 200,
) -> None:
    if train_csv is not None and test_csv is not None:
        train_df = pd.read_csv(train_csv)
        test_df = pd.read_csv(test_csv)
        validate_dataset(train_df)
        validate_dataset(test_df)

        X_train = train_df[FEATURE_COLUMNS].copy()
        y_train = train_df[LABEL_COLUMN].astype(int).copy()
        X_test = test_df[FEATURE_COLUMNS].copy()
        y_test = test_df[LABEL_COLUMN].astype(int).copy()
        total_row_count = len(train_df) + len(test_df)
    else:
        if not input_csvs:
            raise ValueError("Either input_csvs or both train_csv/test_csv must be provided.")
        df = load_feature_csvs(input_csvs)
        validate_dataset(df)

        X = df[FEATURE_COLUMNS].copy()
        y = df[LABEL_COLUMN].astype(int).copy()

        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=test_size,
            random_state=random_state,
            stratify=y if y.nunique() > 1 else None,
        )
        total_row_count = len(df)

    model = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
        n_jobs=1,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    metrics = {
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_test, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
    }

    print("Training complete.")
    print(json.dumps(metrics, indent=2))
    print(classification_report(y_test, y_pred, digits=4))

    model_output.parent.mkdir(parents=True, exist_ok=True)
    metadata_output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_output)

    metadata = {
        "feature_columns": FEATURE_COLUMNS,
        "label_column": LABEL_COLUMN,
        "row_count": int(total_row_count),
        "train_row_count": int(len(X_train)),
        "test_row_count": int(len(X_test)),
        "metrics": metrics,
    }
    with open(metadata_output, "w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=2, ensure_ascii=False)

    importance_df = (
        pd.DataFrame(
            {
                "feature": FEATURE_COLUMNS,
                "importance": model.feature_importances_,
            }
        )
        .sort_values("importance", ascending=False)
        .reset_index(drop=True)
    )
    importance_path = metadata_output.with_name("feature_importance.csv")
    importance_df.to_csv(importance_path, index=False)

    print(f"Saved model to: {model_output}")
    print(f"Saved metadata to: {metadata_output}")
    print(f"Saved feature importance to: {importance_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train a RandomForest model on extracted DDoS feature CSVs.")
    parser.add_argument("--input-csv", type=Path, nargs="+", default=None, help="One or more feature CSV files.")
    parser.add_argument("--train-csv", type=Path, default=None, help="Prebuilt train dataset CSV.")
    parser.add_argument("--test-csv", type=Path, default=None, help="Prebuilt test dataset CSV.")
    parser.add_argument("--model-output", type=Path, default=Path("models/random_forest.joblib"), help="Output model path.")
    parser.add_argument("--metadata-output", type=Path, default=Path("models/model_metadata.json"), help="Output metadata path.")
    parser.add_argument("--test-size", type=float, default=0.2, help="Test split ratio.")
    parser.add_argument("--n-estimators", type=int, default=200, help="Number of trees in the forest.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    train_model(
        input_csvs=args.input_csv,
        model_output=args.model_output,
        metadata_output=args.metadata_output,
        train_csv=args.train_csv,
        test_csv=args.test_csv,
        test_size=args.test_size,
        n_estimators=args.n_estimators,
    )
