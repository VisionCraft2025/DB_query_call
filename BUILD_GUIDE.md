# Build Guide - Remote Query Tool

## 시스템 요구사항

- Ubuntu 20.04+ 또는 유사한 Linux 배포판
- Qt6 개발 환경
- MQTT 클라이언트 라이브러리
- CMake 3.16+
- C++17 지원 컴파일러

## 의존성 설치

### 1. Qt6 설치
```bash
sudo apt update
sudo apt install qt6-base-dev qt6-tools-dev cmake build-essential
```

### 2. Qt MQTT 모듈 설치
```bash
# Qt6 MQTT 모듈 설치
sudo apt install libqt6mqtt6-dev

# 또는 소스에서 빌드하는 경우
# git clone https://github.com/qt/qtmqtt.git
# cd qtmqtt
# mkdir build && cd build
# cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
# make -j$(nproc)
# sudo make install
```

### 3. JSON 라이브러리 설치
```bash
sudo apt install nlohmann-json3-dev
```

## 빌드 과정

### 1. 빌드 디렉토리 생성
```bash
cd /home/kwon/Programming/DB/db_test/factory_monitor/db_query_call
mkdir build
cd build
```

### 2. CMake 설정
```bash
cmake ..
```

### 3. 컴파일
```bash
make -j$(nproc)
```

### 4. 실행
```bash
./db_query_call
```

## 문제 해결

### Qt6 관련 오류
```bash
# Qt6 환경 변수 설정
export QT_SELECT=qt6
export CMAKE_PREFIX_PATH=/usr/lib/x86_64-linux-gnu/cmake/Qt6
```

### Qt MQTT 모듈 찾을 수 없는 경우
```bash
# Qt6 모듈 경로 확인
find /usr -name "Qt6MqttConfig.cmake" 2>/dev/null

# CMake 경로에 Qt6 추가
export CMAKE_PREFIX_PATH=/usr/lib/x86_64-linux-gnu/cmake/Qt6:$CMAKE_PREFIX_PATH

# 또는 qtmqtt가 ~/dev/cpp_libs/qtmqtt에 있는 경우
export CMAKE_PREFIX_PATH=~/dev/cpp_libs/qtmqtt/build:$CMAKE_PREFIX_PATH
```

### JSON 헤더 찾을 수 없는 경우
```bash
# nlohmann/json 헤더 위치 확인
find /usr -name "json.hpp" 2>/dev/null

# 일반적인 위치
sudo ln -s /usr/include/nlohmann/json.hpp /usr/local/include/
```

## 실행 전 확인사항

1. **MQTT 브로커 실행 확인**
   ```bash
   # Mosquitto 상태 확인
   systemctl status mosquitto
   
   # 포트 확인
   netstat -tlnp | grep 1883
   ```

2. **db_mqtt 프로그램 실행 확인**
   ```bash
   # db_mqtt가 실행 중인지 확인
   ps aux | grep db_mqtt
   ```

3. **네트워크 연결 확인**
   ```bash
   # MQTT 브로커 연결 테스트
   mosquitto_pub -h mqtt.kwon.pics -t test -m "hello"
   ```

## 사용법

1. 프로그램 실행 후 MQTT 브로커 주소 입력
2. "Connect" 버튼 클릭하여 연결
3. 쿼리 조건 설정 (디바이스, 로그 레벨, 시간 범위 등)
4. "Send Query" 버튼 클릭하여 쿼리 전송
5. 결과 테이블에서 로그 데이터 확인

## 디버깅

### 상세 로그 확인
```bash
# 환경 변수로 디버그 모드 활성화
export QT_LOGGING_RULES="*.debug=true"
./db_query_call
```

### MQTT 메시지 모니터링
```bash
# 모든 MQTT 메시지 모니터링
mosquitto_sub -h mqtt.kwon.pics -t '#' -v

# 쿼리 관련 메시지만 모니터링
mosquitto_sub -h mqtt.kwon.pics -t 'factory/query/#' -v
```