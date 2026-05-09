# Model Pipeline

이 프로젝트의 현재 최소 학습 파이프라인은 아래 순서로 동작한다.

1. `CIC 원본 CSV -> 운영 가능 feature subset 추출`
2. `train/test dataset 생성`
3. `RandomForest 학습`
4. `학습된 모델 -> 새로운 feature CSV 예측`

## 1. 학습용 train dataset 생성

```powershell
python -m src.features.prepare_cic_csv_dataset `
  --input-dir "G:\인지프 프로젝트\data\csv\01-12" `
  --output-csv data/processed/train_dataset.csv `
  --metadata-output data/processed/train_dataset_metadata.json `
  --max-benign-rows-per-file 1000 `
  --max-attack-rows-per-file 4000
```

## 2. 평가용 test dataset 생성

```powershell
python -m src.features.prepare_cic_csv_dataset `
  --input-dir "G:\인지프 프로젝트\data\csv\03-11" `
  --output-csv data/processed/test_dataset.csv `
  --metadata-output data/processed/test_dataset_metadata.json `
  --max-benign-rows-per-file 1000 `
  --max-attack-rows-per-file 4000
```

## 3. 모델 학습

```powershell
python -m src.models.train_model `
  --train-csv data/processed/train_dataset.csv `
  --test-csv data/processed/test_dataset.csv `
  --model-output models/random_forest.joblib `
  --metadata-output models/model_metadata.json
```

## 4. 예측

```powershell
python -m src.models.predict_flow `
  --model-path models/random_forest.joblib `
  --input-csv data/processed/test_dataset.csv `
  --output-csv data/processed/predictions.csv
```
