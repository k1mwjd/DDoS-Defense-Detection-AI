# Final CSV Feature Specification

학습은 CIC 원본 CSV 전체를 그대로 사용하지 않고, VM 환경에서 다시 계산 가능한 flow 기반 feature만 사용한다.

## 최종 feature 목록

| 모델 컬럼 | 원본 CSV 컬럼 | 의미 | VM 재계산 가능 여부 |
| --- | --- | --- | --- |
| `destination_port` | `Destination Port` | 목적지 포트 | 가능 |
| `protocol` | `Protocol` | L4 프로토콜 번호 | 가능 |
| `flow_duration` | `Flow Duration` | flow 지속 시간 | 가능 |
| `total_fwd_packets` | `Total Fwd Packets` | 정방향 패킷 수 | 가능 |
| `total_backward_packets` | `Total Backward Packets` | 역방향 패킷 수 | 가능 |
| `total_length_fwd_packets` | `Total Length of Fwd Packets` | 정방향 바이트 수 | 가능 |
| `total_length_bwd_packets` | `Total Length of Bwd Packets` | 역방향 바이트 수 | 가능 |
| `flow_bytes_per_s` | `Flow Bytes/s` | flow 초당 바이트 수 | 가능 |
| `flow_packets_per_s` | `Flow Packets/s` | flow 초당 패킷 수 | 가능 |
| `fwd_packets_per_s` | `Fwd Packets/s` | 정방향 초당 패킷 수 | 가능 |
| `bwd_packets_per_s` | `Bwd Packets/s` | 역방향 초당 패킷 수 | 가능 |
| `min_packet_length` | `Min Packet Length` | 최소 패킷 길이 | 가능 |
| `max_packet_length` | `Max Packet Length` | 최대 패킷 길이 | 가능 |
| `packet_length_mean` | `Packet Length Mean` | 평균 패킷 길이 | 가능 |
| `packet_length_std` | `Packet Length Std` | 패킷 길이 표준편차 | 가능 |
| `syn_flag_count` | `SYN Flag Count` | SYN 플래그 수 | 가능 |
| `rst_flag_count` | `RST Flag Count` | RST 플래그 수 | 가능 |
| `ack_flag_count` | `ACK Flag Count` | ACK 플래그 수 | 가능 |
| `average_packet_size` | `Average Packet Size` | 평균 패킷 크기 | 가능 |
| `down_up_ratio` | `Down/Up Ratio` | 정/역방향 비율 | 가능 |

## 제외한 컬럼 유형

- `Source IP`, `Destination IP`, `Flow ID`, `Timestamp`
  - 식별자 성격이 강해서 일반화에 불리함
- `Active Mean`, `Idle Mean`, `Fwd/Bwd IAT ...`
  - 실시간 구현 난이도가 높고 정의 일치가 까다로움
- `Init_Win_bytes_forward`, `SimillarHTTP`, `Inbound`
  - 재현성 또는 일반화 측면에서 부적절함

## 현재 판단

- `학습용 데이터는 CSV 사용`
- `최종 운영 입력은 실시간 flow feature`
- `따라서 학습에 쓰는 컬럼은 운영 시 VM에서 다시 계산 가능한 것만 허용`
