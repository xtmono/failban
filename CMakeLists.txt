cmake_minimum_required(VERSION 3.11)

# Auto-detect OpenWrt cross-compilation environment
if(DEFINED ENV{STAGING_DIR})
    message(STATUS "Cross-compiling for OpenWrt using STAGING_DIR: $ENV{STAGING_DIR}")

    set(CMAKE_SYSTEM_NAME Linux)
    set(CMAKE_SYSTEM_PROCESSOR aarch64)

    set(STAGING_DIR $ENV{STAGING_DIR})

    # Find the toolchain directory
    file(GLOB TOOLCHAIN_DIRS "${STAGING_DIR}/toolchain-*")
    if(TOOLCHAIN_DIRS)
        list(GET TOOLCHAIN_DIRS 0 TOOLCHAIN_DIR)
        set(TOOLCHAIN_BIN "${TOOLCHAIN_DIR}/bin")
        message(STATUS "Found toolchain: ${TOOLCHAIN_DIR}")

        # Find the gcc compiler
        file(GLOB GCC_COMPILERS "${TOOLCHAIN_BIN}/*-openwrt-linux-*-gcc")
        if(NOT GCC_COMPILERS)
            file(GLOB GCC_COMPILERS "${TOOLCHAIN_BIN}/*-gcc")
        endif()

        if(GCC_COMPILERS)
            list(GET GCC_COMPILERS 0 CMAKE_C_COMPILER)
            string(REGEX REPLACE "-gcc$" "-g++" CMAKE_CXX_COMPILER "${CMAKE_C_COMPILER}")
            message(STATUS "Using C compiler: ${CMAKE_C_COMPILER}")
            message(STATUS "Using CXX compiler: ${CMAKE_CXX_COMPILER}")
        else()
            message(FATAL_ERROR "Could not find GCC compiler in ${TOOLCHAIN_BIN}")
        endif()

        set(CMAKE_FIND_ROOT_PATH "${TOOLCHAIN_DIR}")

        # Search for programs in the build host directories
        set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
        # Search for libraries and headers in the target directories
        set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
        set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
        set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
    else()
        message(FATAL_ERROR "Could not find toolchain directory in ${STAGING_DIR}/toolchain-*")
    endif()
else()
    message(STATUS "STAGING_DIR not set. Building for native host.")
endif()

project(failban C)

# Suppress FetchContent_Populate deprecation warning
# We need to use FetchContent_Populate because inih doesn't provide CMakeLists.txt
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
add_compile_options(-Wall -Wextra -O2)

# FetchContent module to download inih
include(FetchContent)

FetchContent_Declare(
    inih
    GIT_REPOSITORY https://github.com/benhoyt/inih.git
    GIT_TAG r58  # Latest stable release as of now
)

# Download inih but don't try to build it yet (it doesn't have CMakeLists.txt)
FetchContent_GetProperties(inih)
if(NOT inih_POPULATED)
    FetchContent_Populate(inih)
endif()

# Create inih library manually from the downloaded sources
add_library(inih STATIC
    ${inih_SOURCE_DIR}/ini.c
)

# Set include directories for inih
target_include_directories(inih PUBLIC
    ${inih_SOURCE_DIR}
)

# Define the executable
add_executable(failban
    failban.c
)

# Link inih library
target_link_libraries(failban PRIVATE inih)

# Install target (optional)
install(TARGETS failban DESTINATION bin)

