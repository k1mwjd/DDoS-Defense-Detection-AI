from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from typing import Dict
from typing import Optional

import joblib
import pandas as pd

from app.config import DEFAULT_MODEL_PATH, FEATURE_COLUMNS


@dataclass
class InferenceResult:
    prediction: int
    attack_probability: float


class ModelInferenceService:
    def __init__(self, model_path: Optional[Path] = None) -> None:
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self._model = None

    def load(self) -> None:
        if self._model is None:
            if not self.model_path.exists():
                raise FileNotFoundError(self.model_path)
            self._model = joblib.load(self.model_path)

    def predict_from_feature_dict(self, features: Dict[str, Any]) -> InferenceResult:
        self.load()
        missing_columns = [column for column in FEATURE_COLUMNS if column not in features]
        if missing_columns:
            raise KeyError(f"Missing required feature columns: {missing_columns}")

        df = pd.DataFrame([[features[column] for column in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)
        prediction = int(self._model.predict(df)[0])
        attack_probability = float(self._model.predict_proba(df)[0][1])
        return InferenceResult(prediction=prediction, attack_probability=attack_probability)

    def predict_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        self.load()
        missing_columns = [column for column in FEATURE_COLUMNS if column not in df.columns]
        if missing_columns:
            raise KeyError(f"Missing required feature columns: {missing_columns}")

        result = df.copy()
        result["prediction"] = self._model.predict(result[FEATURE_COLUMNS]).astype(int)
        result["attack_probability"] = self._model.predict_proba(result[FEATURE_COLUMNS])[:, 1].astype(float)
        return result
