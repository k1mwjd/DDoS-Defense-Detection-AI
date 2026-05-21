# AI 기반 DDoS 탐지 모델

## 프로젝트 개요
본 프로젝트는 CIC 계열 DDoS 트래픽 CSV 데이터셋을 기반으로 정상 트래픽과 공격 트래픽을 구분하는 이진 분류 모델을 학습하는 것을 목표로 한다.

현재 구현 범위는 다음과 같다.

- CSV 전처리
- feature subset 구성
- Random Forest 모델 학습
- 성능 평가
- 학습된 모델 저장
- 저장된 모델 기반 CSV 예측
- FastAPI 기반 예측 API
- 위험도 계산 및 차단 판단 API

## 시스템 요구사항
- 운영 체제: Windows 11
- 가상화 환경: VMware
- 프로그래밍 언어: Python
- 사용 데이터셋: CIC 계열 DDoS 트래픽 CSV 데이터
- 필수 라이브러리
  - pandas
  - numpy
  - scikit-learn
  - joblib
  - scapy
  - fastapi
  - uvicorn

## Directory layout

```text
AI DDos Detection
├── data
│   ├── raw
│   ├── processed
│   └── realtime_logs
├── docs
├── models
└── src
    ├── features
    ├── models
    ├── firewall
    ├── api
    └── utils
```

## 데이터 사용 방식
- 학습용 데이터: `01-12`
- 테스트용 데이터: `03-11`

학습과 평가는 날짜를 분리하여 진행하며, `03-11` 데이터는 테스트 전용으로 사용한다.

## 사용 feature
- `destination_port`
- `protocol`
- `flow_duration`
- `total_fwd_packets`
- `total_backward_packets`
- `total_length_fwd_packets`
- `total_length_bwd_packets`
- `flow_bytes_per_s`
- `flow_packets_per_s`
- `fwd_packets_per_s`
- `bwd_packets_per_s`
- `min_packet_length`
- `max_packet_length`
- `packet_length_mean`
- `packet_length_std`
- `syn_flag_count`
- `rst_flag_count`
- `ack_flag_count`
- `average_packet_size`
- `down_up_ratio`

## 핵심 파일
- `src/features/prepare_cic_csv_dataset.py`: CIC 원본 CSV 전처리 및 학습용 데이터셋 생성
- `src/models/train_model.py`: Random Forest 모델 학습 및 성능 평가
- `src/models/predict_flow.py`: 저장된 모델을 이용한 CSV 기반 예측
- `src/models/inference_service.py`: 저장된 모델 로딩 및 공통 추론 처리
- `src/firewall/defense.py`: 위험도 계산 및 차단 판단 로직
- `src/api/main.py`: FastAPI 백엔드 진입점
- `src/utils/config.py`: 공통 경로 및 feature 설정

## 백엔드 구조

요청 처리 흐름은 다음과 같다.

```
POST /predict
  └─ ModelInferenceService.predict_from_feature_dict()
       └─ Random Forest 모델 추론 → prediction, attack_probability 반환
  └─ DefenseManager.evaluate()
       └─ risk_score 계산 → risk_level 분류 → 차단 여부 결정
```

### 위험도 분류 기준

`attack_probability`를 0~100 점수로 변환한 뒤 아래 기준으로 분류한다.

| risk_level | risk_score 범위 |
|------------|----------------|
| low        | 0 ~ 39         |
| medium     | 40 ~ 69        |
| high       | 70 ~ 89        |
| critical   | 90 ~ 100       |

`prediction == 1`이고 `risk_score >= threshold`인 경우에만 차단이 실행된다.

### 환경 변수

| 변수명                          | 기본값                              | 설명                              |
|---------------------------------|-------------------------------------|-----------------------------------|
| `AI_DDOS_MODEL_PATH`            | `models/random_forest_medium.joblib` | 모델 파일 경로                    |
| `AI_DDOS_DEFENSE_THRESHOLD`     | `70.0`                              | 차단 실행 최소 risk_score         |
| `AI_DDOS_BLOCK_SECONDS`         | `600`                               | 차단 유지 시간(초)                |
| `AI_DDOS_ENABLE_WINDOWS_FIREWALL` | `false`                           | Windows 방화벽 규칙 자동 적용 여부 |

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

## 백엔드 실행 및 테스트
### 1. FastAPI 서버 실행
```powershell
.\.venv\Scripts\python.exe -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. 상태 확인
```powershell
Invoke-WebRequest http://127.0.0.1:8000/health
```

### 3. 예측 API 테스트
```powershell
$body = @{
  source_ip = "192.168.0.10"
  features = @{
    destination_port = 80
    protocol = 6
    flow_duration = 1200
    total_fwd_packets = 50
    total_backward_packets = 3
    total_length_fwd_packets = 4000
    total_length_bwd_packets = 180
    flow_bytes_per_s = 3500
    flow_packets_per_s = 44
    fwd_packets_per_s = 41
    bwd_packets_per_s = 3
    min_packet_length = 60
    max_packet_length = 1500
    packet_length_mean = 78
    packet_length_std = 33
    syn_flag_count = 45
    rst_flag_count = 0
    ack_flag_count = 2
    average_packet_size = 76
    down_up_ratio = 0.06
  }
} | ConvertTo-Json -Depth 3

Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/predict" `
  -Method Post `
  -Body $body `
  -ContentType "application/json"
```

### 4. 차단 목록 조회
```powershell
Invoke-RestMethod http://127.0.0.1:8000/blocked-sources
```

### 5. 특정 IP 차단 해제
```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/blocked-sources/192.168.0.10" `
  -Method Delete
```

## 현재 결과
- train rows: `27392`
- test rows: `17500`
- total rows: `44892`

평가 지표
- Precision: `0.9899`
- Recall: `0.9689`
- F1-score: `0.9792`

혼동행렬
- TN = `3361`
- FP = `139`
- FN = `436`
- TP = `13564`
