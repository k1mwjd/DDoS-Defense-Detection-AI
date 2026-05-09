  # AI-DDos-Detection

  ## 프로젝트 개요
  본 프로젝트는 외부망에서 유입되는 네트워크 트래픽을 분석하여 DDoS 공격 여부를 판단하고, 정상으로 판별된 트래픽만 내부
  서버망으로 전달하는 AI 기반 DDoS 방화벽 구현을 목표로 한다.

  이를 위해 CIC 계열 네트워크 트래픽 CSV 데이터셋을 사용하여 정상 트래픽과 공격 트래픽을 구분하는 이진 분류 모델을 학습
  하였다. 모델은 랜덤 포레스트(Random Forest) 분류기를 기반으로 구성하였으며, 데이터 전처리, feature 선택, 모델 학습, 성
  능 평가, 학습 모델 저장까지의 과정을 구현하였다.

  또한 실제 네트워크 환경에 적용할 수 있도록, 학습에 사용되는 feature는 이후 VM 환경에서도 다시 계산 가능한 flow 기반
  feature 위주로 선정하였다. 이를 바탕으로 향후에는 실시간 네트워크 트래픽 분석 및 차단 기능까지 확장하는 것을 목표로 한
  다.

  ## 시스템 요구사항
  - OS: Windows 11 Pro, 64-bit
  - Virtual-Environments: VMware® Workstation Pro 25.0.0.24995812
  - Language: Python
  - Dataset: CIC-DDoS 2019
  - 필수 라이브러리:
    - pandas
    - numpy
    - scikit-learn
    - joblib
    - scapy


## Directory layout

```
AI-DDos-Detection
└── AI_engine
    ├── data                   # Project data directory
    │   ├── raw                # Raw input data or temporary source files
    │   ├── processed          # Preprocessed train/test CSV files and derived outputs
    │   └── realtime_logs      # Runtime or experiment log outputs
    ├── docs                   # Project documentation and progress notes
    ├── models                 # Trained Random Forest models and evaluation metadata
    └── src                    # Source code
        ├── capture            # Packet-related modules
        ├── features           # Dataset preprocessing and feature preparation code
        ├── firewall           # Firewall-related extension modules
        ├── models             # Training and prediction code
        └── utils              # Shared configuration and helper code
```


## 학습 파이프라인

### 1. 학습 데이터셋 생성

```powershell
.\.venv\Scripts\python.exe -m src.features.prepare_cic_csv_dataset `
  --input-dir ..\data\csv\01-12 `
  --output-csv data\processed\train_dataset_medium.csv `
  --metadata-output data\processed\train_dataset_medium_metadata.json `
  --max-benign-rows-per-file 500 `
  --max-attack-rows-per-file 2000 `
  --chunk-size 50000
```

### 2. 테스트 데이터셋 생성

```powershell
.\.venv\Scripts\python.exe -m src.features.prepare_cic_csv_dataset `
  --input-dir ..\data\csv\03-11 `
  --output-csv data\processed\test_dataset_medium.csv `
  --metadata-output data\processed\test_dataset_medium_metadata.json `
  --max-benign-rows-per-file 500 `
  --max-attack-rows-per-file 2000 `
  --chunk-size 50000
```

### 3. 모델 학습 및 평가

```powershell
.\.venv\Scripts\python.exe -m src.models.train_model `
  --train-csv data\processed\train_dataset_medium.csv `
  --test-csv data\processed\test_dataset_medium.csv `
  --model-output models\random_forest_medium.joblib `
  --metadata-output models\model_metadata_medium.json `
  --n-estimators 300
```

## 현재 결과

확장 데이터셋 기준:

- train rows: `27392`
- test rows: `17500`
- total rows: `44892`

평가 지표:

- Precision: `0.9899`
- Recall: `0.9689`
- F1-score: `0.9792`

혼동행렬:

- TN = `3361`
- FP = `139`
- FN = `436`
- TP = `13564`

이 결과는 라벨이 있는 테스트 CSV를 기준으로 계산한 값이며, 현재 제시하는 모델 성능 결과는 위 평가 결과를 기준으로 한다.
