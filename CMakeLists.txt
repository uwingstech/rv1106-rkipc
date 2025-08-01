cmake_minimum_required(VERSION 3.5)

set(CMAKE_TOOLCHAIN_FILE ${CMAKE_SOURCE_DIR}/cmake/toolchain.cmake)

project(rkipc)

set(RKIPC_CROSS_COMPILE  "arm-rockchip830-linux-uclibcgnueabihf")
set(PROJECT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# Build type
set(CMAKE_BUILD_TYPE Release)

# Install prefix
set(CMAKE_INSTALL_PREFIX "${PROJECT_SOURCE_DIR}/out")

set(CMAKE_FIND_ROOT_PATH
    "${PROJECT_SOURCE_DIR}/out"
    ${TOOLCHAIN_SYSROOT}
)

set(CMAKE_SYSROOT ${TOOLCHAIN_SYSROOT})

# Find root path modes
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_NO_SYSTEM_FROM_IMPORTED ON)

# Compiler flags and include directories
set(INCLUDE_DIRS
    "${PROJECT_SOURCE_DIR}/media/include"
    "${PROJECT_SOURCE_DIR}/media/include/libdrm"
    "${PROJECT_SOURCE_DIR}/media/include/rkaiq"
    "${PROJECT_SOURCE_DIR}/media/include/rkaiq/uAPI"
    "${PROJECT_SOURCE_DIR}/media/include/rkaiq/uAPI2"
    "${PROJECT_SOURCE_DIR}/media/include/rkaiq/algos"
    "${PROJECT_SOURCE_DIR}/media/include/rkaiq/common"
    "${PROJECT_SOURCE_DIR}/media/include/rkaiq/xcore"
    "${PROJECT_SOURCE_DIR}/media/include/rkaiq/iq_parser"
    "${PROJECT_SOURCE_DIR}/media/include/rkaiq/iq_parser_v2"
    "${PROJECT_SOURCE_DIR}/media/include"
    "${PROJECT_SOURCE_DIR}/include/freetype2"
    "${PROJECT_SOURCE_DIR}/media/include/easymedia"
)

set(LIBRARY_DIRS
    "${PROJECT_SOURCE_DIR}/media/lib"
    "${PROJECT_SOURCE_DIR}/lib"
)

include_directories(${INCLUDE_DIRS})
link_directories(${LIBRARY_DIRS})

# Common compile definitions and flags
add_compile_definitions(
    _LARGEFILE_SOURCE
    _LARGEFILE64_SOURCE
    _FILE_OFFSET_BITS=64
)

set(LINK_FLAGS       "${LINK_FLAGS}  -Wl,-rpath-link,${PROJECT_SOURCE_DIR}/media/lib:${PROJECT_SOURCE_DIR}/media/root/usr/lib:/tmp/luckfox-pico/project/app/out/lib")
set(CMAKE_C_FLAGS    "${CMAKE_C_FLAGS} ${LINK_FLAGS}")
set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${LINK_FLAGS}")

# 自訂定義
add_definitions(-DCOMPILE_FOR_RV1106_IPC)
add_definitions(-DRKIPC_CROSS_COMPILE="arm-rockchip830-linux-uclibcgnueabihf")

# generate version info
include(cmake/Version.cmake)


if(${CMAKE_BUILD_TYPE} STREQUAL Debug)
	message(STATUS "CMAKE_BUILD_TYPE is ${CMAKE_BUILD_TYPE}")
	add_definitions(-g -ggdb -gdwarf -funwind-tables -rdynamic -O0)
	add_definitions(-fno-stack-protector -fno-omit-frame-pointer)
elseif(${CMAKE_BUILD_TYPE} STREQUAL Release)
	message(STATUS "CMAKE_BUILD_TYPE is ${CMAKE_BUILD_TYPE}")
elseif(${CMAKE_BUILD_TYPE} STREQUAL RelWithDebInfo)
	message(STATUS "CMAKE_BUILD_TYPE is ${CMAKE_BUILD_TYPE}")
elseif(${CMAKE_BUILD_TYPE} STREQUAL MinSizeRel)
	message(STATUS "CMAKE_BUILD_TYPE is ${CMAKE_BUILD_TYPE}")
	add_definitions(-Os)
endif()

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fdata-sections -ffunction-sections -Wl,-rpath-link,${PROJECT_SOURCE_DIR}/lib/arm-rockchip830-linux-uclibcgnueabihf")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdata-sections -ffunction-sections -Wl,-rpath-link,${PROJECT_SOURCE_DIR}/lib/arm-rockchip830-linux-uclibcgnueabihf")
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections -Wl,--as-needed")

add_subdirectory(src/rv1106_ipc)

