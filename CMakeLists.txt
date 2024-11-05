cmake_minimum_required(VERSION 3.5.0)

project(n4_cpp VERSION 0.1.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(./include)
include_directories(.)

add_executable(n4
    src/main.cpp
    src/n4.cpp
    src/socket.cpp
)

