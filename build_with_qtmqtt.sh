#!/bin/bash

# qtmqtt 라이브러리 빌드 및 프로젝트 빌드 스크립트

set -e  # 오류 발생 시 스크립트 중단

QTMQTT_DIR="$HOME/dev/cpp_libs/qtmqtt"
PROJECT_DIR="$(pwd)"

echo "=== Qt MQTT 라이브러리 빌드 ==="

# qtmqtt 디렉토리 확인
if [ ! -d "$QTMQTT_DIR" ]; then
    echo "Error: qtmqtt directory not found at $QTMQTT_DIR"
    echo "Please clone qtmqtt repository first:"
    echo "  mkdir -p ~/dev/cpp_libs"
    echo "  cd ~/dev/cpp_libs"
    echo "  git clone https://github.com/qt/qtmqtt.git"
    exit 1
fi

# qtmqtt 빌드
cd "$QTMQTT_DIR"

if [ ! -d "build" ]; then
    mkdir build
fi

cd build

echo "Configuring qtmqtt..."
cmake .. -DCMAKE_BUILD_TYPE=Release

echo "Building qtmqtt..."
make -j$(nproc)

echo "=== 프로젝트 빌드 ==="

# 원래 프로젝트 디렉토리로 돌아가기
cd "$PROJECT_DIR"

# 빌드 디렉토리 생성
if [ ! -d "build" ]; then
    mkdir build
fi

cd build

echo "Configuring project..."
cmake ..

echo "Building project..."
make -j$(nproc)

echo "=== 빌드 완료 ==="
echo "실행 파일: $PROJECT_DIR/build/db_query_call"