cmake_minimum_required(3.22)

project(covertcomm_native LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(covertcomm_native SHARED
    native_guard.cpp
)

target_link_libraries(covertcomm_native
    log
)