# Factory Remote Query Tool (MQTT)

외부에서 MQTT를 통해 공장 로그 데이터를 조회하는 Qt 기반 GUI 애플리케이션입니다.

## 주요 기능

- **MQTT 기반 원격 쿼리**: 외부에서 안전하게 로그 데이터 조회
- **실시간 연결 상태 모니터링**: MQTT 브로커 연결 상태 실시간 확인
- **다양한 필터링 옵션**: 디바이스, 로그 레벨, 코드, 심각도, 시간 범위 등
- **구조화된 결과 표시**: 테이블 형태로 정리된 로그 데이터 표시
- **상세 정보 보기**: 선택한 로그의 상세 정보 표시

## MQTT 토픽 구조

### 쿼리 요청
```
factory/query/logs/request
```

### 쿼리 응답
```
factory/query/logs/response
```

## 쿼리 페이로드 형식

### 요청 (Request)
```json
{
  "query_id": "Q-01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "query_type": "logs",
  "client_id": "remote_query_12345",
  "filters": {
    "device_id": "robot_arm_01",
    "log_level": "error",
    "log_code": "TMP",
    "severity": "HIGH",
    "time_range": {
      "start": 1672531200000,
      "end": 1672617600000
    },
    "limit": 100
  }
}
```

### 응답 (Response)
```json
{
  "query_id": "Q-01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "status": "success",
  "count": 25,
  "data": [
    {
      "_id": "RA01-TMP-01ARZ3NDEKTSV4RRFFQ69G5FAV",
      "device_id": "robot_arm_01",
      "device_name": "Assembly Robot #1",
      "log_level": "error",
      "log_code": "TMP",
      "severity": "HIGH",
      "message": "Motor overheating detected",
      "timestamp": 1672531200000,
      "location": "Line A - Station 3"
    }
  ]
}
```

## 빌드 방법

### 자동 빌드 (권장)
```bash
cd /home/kwon/Programming/DB/db_test/factory_monitor/db_query_call
./build_with_qtmqtt.sh
```

### 수동 빌드
```bash
# 1. qtmqtt 라이브러리 빌드 (최초 1회)
cd ~/dev/cpp_libs/qtmqtt
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# 2. 프로젝트 빌드
cd /home/kwon/Programming/DB/db_test/factory_monitor/db_query_call
mkdir build && cd build
cmake ..
make
```

## 실행 방법

```bash
./db_query_call
```

## 사용 방법

1. **MQTT 연결**: 브로커 주소 입력 후 "Connect" 버튼 클릭
2. **쿼리 설정**: 필터 조건 설정 (디바이스, 로그 레벨, 시간 범위 등)
3. **쿼리 전송**: "Send Query" 버튼 클릭
4. **결과 확인**: 테이블에서 결과 확인, 행 선택 시 상세 정보 표시

## 보안 특징

- **MongoDB 직접 접근 차단**: MQTT를 통한 간접 접근만 허용
- **클라이언트 ID 기반 식별**: 각 클라이언트별 고유 ID 생성
- **쿼리 ID 추적**: 요청-응답 매칭을 통한 안전한 통신
- **연결 상태 모니터링**: 실시간 연결 상태 확인

## 의존성

- Qt6 (Core, Widgets, Network)
- Qt6 MQTT (qtmqtt 라이브러리)
- nlohmann/json

## 설치 요구사항

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install qt6-base-dev qt6-tools-dev cmake build-essential nlohmann-json3-dev
```

### qtmqtt 라이브러리
```bash
# qtmqtt 소스 다운로드
mkdir -p ~/dev/cpp_libs
cd ~/dev/cpp_libs
git clone https://github.com/qt/qtmqtt.git
```