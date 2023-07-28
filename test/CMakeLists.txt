cmake_minimum_required(VERSION 3.10)
project(cflag_test LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
# Avoid warning about DOWNLOAD_EXTRACT_TIMESTAMP in CMake 3.24:
if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
    cmake_policy(SET CMP0135 NEW)
endif()
enable_testing()
FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.13.0.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
aux_source_directory(src test_src)
add_executable(${PROJECT_NAME} ${test_src})

target_include_directories(${PROJECT_NAME} SYSTEM AFTER PRIVATE ../include ../src src)

target_link_libraries(
        ${PROJECT_NAME}
        GTest::gtest_main
        ckit
)
set_property(TARGET ${PROJECT_NAME} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
include(GoogleTest)
gtest_discover_tests(${PROJECT_NAME})