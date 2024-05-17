cmake_minimum_required(VERSION 3.27)
project(conn_mapping)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 COMPONENTS Core REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_search_module(PCAP REQUIRED libpcap)

add_executable(conn_mapping
        main.cpp
        ConnectionMapping.cpp
        ConnectionMapping.h
        PcapHandler.cpp
        PcapHandler.h
)

target_link_libraries(conn_mapping
        Qt6::Core
        ${PCAP_LIBRARIES}
)

target_include_directories(conn_mapping PRIVATE ${PCAP_INCLUDE_DIRS})
