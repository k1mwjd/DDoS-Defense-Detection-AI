# Model Progress

## 현재 방향

- 학습에는 CIC 원본 CSV를 사용한다.
- 다만 원본 CSV 전체를 그대로 사용하는 것이 아니라, 이후 실제 환경에서도 다시 계산 가능한 feature subset만 사용한다.
- 평가는 `01-12`를 학습용, `03-11`을 테스트용으로 고정하여 진행한다.

## 구현 완료 사항

1. `src/features/prepare_cic_csv_dataset.py`
   - CIC 원본 CSV에서 feature subset 추출
   - `BENIGN/NORMAL -> 0`, 나머지 공격 라벨 `1`로 이진화
   - 대용량 CSV를 chunk 단위로 읽어 샘플링

2. `src/models/train_model.py`
   - RandomForest 기반 학습
   - train/test 분리 입력 지원
   - 성능 메트릭과 feature importance 저장

3. `src/models/predict_flow.py`
   - 학습된 모델로 feature CSV 예측 가능

## 소규모 baseline 학습 결과

### 데이터 구성

- train: `01-12`
- test: `03-11`
- 파일당 샘플 수
  - 정상: `100`
  - 공격: `200`

### 데이터 크기

- train rows: `3300`
- test rows: `2100`
- total rows: `5400`

### 성능

- Precision: `0.9680`
- Recall: `0.9514`
- F1-score: `0.9597`
- Accuracy: `0.9467`

### 혼동행렬

```text
TN = 656
FP = 44
FN = 68
TP = 1332
```

## 중간 규모 학습 결과

### 데이터 구성

- train: `01-12`
- test: `03-11`
- 파일당 샘플 수
  - 정상: `500`
  - 공격: `2000`

### 데이터 크기

- train rows: `27392`
- test rows: `17500`
- total rows: `44892`

### 성능

- Precision: `0.9899`
- Recall: `0.9689`
- F1-score: `0.9792`
- Accuracy: `0.9671`

### 혼동행렬

```text
TN = 3361
FP = 139
FN = 436
TP = 13564
```

## 해석

- 샘플 수를 늘린 뒤 precision, recall, f1-score가 모두 향상되었다.
- `01-12 -> train`, `03-11 -> test`의 교차일자 평가에서도 성능이 유지되어, 현재 feature subset 기반 RandomForest 모델은 1차 기준 모델로 사용할 수 있다.

## 중요 feature 상위권

- `destination_port`
- `min_packet_length`
- `bwd_packets_per_s`
- `total_backward_packets`
- `average_packet_size`
- `packet_length_mean`
- `ack_flag_count`
- `down_up_ratio`

## 현재 상태

현재까지 완료된 범위는 다음과 같다.

- CSV 전처리
- RandomForest 학습
- 평가 지표 생성
- 모델 저장
