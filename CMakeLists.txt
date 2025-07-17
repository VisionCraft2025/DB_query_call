cmake_minimum_required(VERSION 3.16)
project(db_query_call)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# qtmqtt 라이브러리 경로 추가
list(APPEND CMAKE_PREFIX_PATH "$ENV{HOME}/dev/cpp_libs/qtmqtt/build")

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network)
find_package(Qt6 QUIET COMPONENTS Mqtt)

if(NOT Qt6Mqtt_FOUND)
    message(STATUS "Qt6Mqtt not found in system, trying custom path...")
    # 사용자 정의 경로에서 qtmqtt 찾기
    find_path(QTMQTT_INCLUDE_DIR QtMqtt/QMqttClient
        PATHS "$ENV{HOME}/dev/cpp_libs/qtmqtt/build/include"
        NO_DEFAULT_PATH
    )
    
    find_library(QTMQTT_LIBRARY Qt6Mqtt
        PATHS "$ENV{HOME}/dev/cpp_libs/qtmqtt/build/lib/x86_64-linux-gnu"
        NO_DEFAULT_PATH
    )
    
    if(QTMQTT_INCLUDE_DIR AND QTMQTT_LIBRARY)
        message(STATUS "Found custom Qt6Mqtt: ${QTMQTT_LIBRARY}")
        set(Qt6Mqtt_FOUND TRUE)
        # 커스텀 타겟 생성
        add_library(Qt6::Mqtt SHARED IMPORTED)
        set_target_properties(Qt6::Mqtt PROPERTIES
            IMPORTED_LOCATION "${QTMQTT_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${QTMQTT_INCLUDE_DIR}"
        )
    else()
        message(STATUS "QTMQTT_INCLUDE_DIR: ${QTMQTT_INCLUDE_DIR}")
        message(STATUS "QTMQTT_LIBRARY: ${QTMQTT_LIBRARY}")
        message(FATAL_ERROR "Qt6Mqtt not found. Please install Qt6Mqtt or build qtmqtt library.")
    endif()
endif()

# nlohmann/json 헤더 찾기
find_path(NLOHMANN_JSON_INCLUDE_DIR nlohmann/json.hpp)

# Qt 자동 MOC, UIC, RCC 활성화
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

set(SOURCES
    main.cpp
    remote_query_window.cpp
)

set(HEADERS
    remote_query_window.h
)

add_executable(db_query_call ${SOURCES} ${HEADERS})

target_link_libraries(db_query_call PRIVATE
    Qt6::Core 
    Qt6::Widgets
    Qt6::Network
    Qt6::Mqtt
)

target_include_directories(db_query_call PRIVATE 
    ${NLOHMANN_JSON_INCLUDE_DIR}
)
