cmake_minimum_required(VERSION 3.20)
project(paramite VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# vcpkg toolchain
if(DEFINED ENV{HOME})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{HOME}/vcpkg/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")
endif()

# Find packages
find_package(spdlog REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(CLI11 CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS system filesystem)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Compiler flags - only for OUR code, not dependencies
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(PARAMITE_COMPILE_OPTIONS
        -Wall
        -Wextra
        -Wpedantic
        # Don't use -Werror for now
    )
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Core library sources
file(GLOB_RECURSE CORE_SOURCES "src/core/*.cpp")
add_library(paramite_core STATIC ${CORE_SOURCES})
target_include_directories(paramite_core PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_compile_options(paramite_core PRIVATE ${PARAMITE_COMPILE_OPTIONS})
target_link_libraries(paramite_core
    PUBLIC
        spdlog::spdlog
        nlohmann_json::nlohmann_json
        Boost::system
        Boost::filesystem
)

# Utils library sources
file(GLOB_RECURSE UTILS_SOURCES "src/utils/*.cpp")
add_library(paramite_utils STATIC ${UTILS_SOURCES})
target_include_directories(paramite_utils PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_compile_options(paramite_utils PRIVATE ${PARAMITE_COMPILE_OPTIONS})
target_link_libraries(paramite_utils
    PUBLIC
        spdlog::spdlog
        nlohmann_json::nlohmann_json
        OpenSSL::SSL
        OpenSSL::Crypto
        Boost::filesystem
)
target_compile_definitions(paramite_utils PRIVATE HAVE_OPENSSL)

# Monitors library sources
file(GLOB_RECURSE MONITORS_SOURCES "src/monitors/*.cpp")
add_library(paramite_monitors STATIC ${MONITORS_SOURCES})
target_include_directories(paramite_monitors PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_compile_options(paramite_monitors PRIVATE ${PARAMITE_COMPILE_OPTIONS})
target_link_libraries(paramite_monitors
    PUBLIC
        paramite_core
        spdlog::spdlog
        nlohmann_json::nlohmann_json
)

# Analyzers library sources
file(GLOB_RECURSE ANALYZERS_SOURCES "src/analyzers/*.cpp")
add_library(paramite_analyzers STATIC ${ANALYZERS_SOURCES})
target_include_directories(paramite_analyzers PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_compile_options(paramite_analyzers PRIVATE ${PARAMITE_COMPILE_OPTIONS})
target_link_libraries(paramite_analyzers
    PUBLIC
        paramite_core
        paramite_utils
        spdlog::spdlog
        nlohmann_json::nlohmann_json
)

# Parsers library sources
file(GLOB_RECURSE PARSERS_SOURCES "src/parsers/*.cpp")
add_library(paramite_parsers STATIC ${PARSERS_SOURCES})
target_include_directories(paramite_parsers PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_compile_options(paramite_parsers PRIVATE ${PARAMITE_COMPILE_OPTIONS})
target_link_libraries(paramite_parsers
    PUBLIC
        paramite_core
        spdlog::spdlog
        nlohmann_json::nlohmann_json
)

# Reporters library sources
file(GLOB_RECURSE REPORTERS_SOURCES "src/reporters/*.cpp")
add_library(paramite_reporters STATIC ${REPORTERS_SOURCES})
target_include_directories(paramite_reporters PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_compile_options(paramite_reporters PRIVATE ${PARAMITE_COMPILE_OPTIONS})
target_link_libraries(paramite_reporters
    PUBLIC
        paramite_core
        spdlog::spdlog
        nlohmann_json::nlohmann_json
)

# Main executable
add_executable(paramite src/main.cpp)
target_compile_options(paramite PRIVATE ${PARAMITE_COMPILE_OPTIONS})
target_link_libraries(paramite
    PRIVATE
        paramite_core
        paramite_utils
        paramite_monitors
        paramite_analyzers
        paramite_parsers
        paramite_reporters
        CLI11::CLI11
        spdlog::spdlog
        nlohmann_json::nlohmann_json
        Threads::Threads
)

# Platform-specific settings
if(WIN32)
    target_compile_definitions(paramite PRIVATE _WIN32_WINNT=0x0601)
    target_link_libraries(paramite PRIVATE ws2_32)
endif()

# Install rules
install(TARGETS paramite DESTINATION bin)
install(DIRECTORY include/ DESTINATION include)

# Print configuration
message(STATUS "===========================================")
message(STATUS "Paramite Malware Analysis Framework")
message(STATUS "===========================================")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "OpenSSL: ${OPENSSL_VERSION}")
message(STATUS "Build directory: ${CMAKE_BINARY_DIR}")
message(STATUS "===========================================")