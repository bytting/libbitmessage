project(libbitmessage)

cmake_minimum_required(VERSION 2.8)

set(LIBRARY_NAME ${PROJECT_NAME})
set(MAJOR_VERSION 0)
set(MINOR_VERSION 1)
set(PATCH_VERSION 0)
set(LIBRARY_VERSION ${MAJOR_VERSION}.${MINOR_VERSION}-${PATCH_VERSION})

set(CMAKE_CXX_FLAGS "-std=c++11 -g -Wall")

set(CMAKE_BUILD_TYPE Debug)

configure_file(${CMAKE_SOURCE_DIR}/src/config.h.cmake ${CMAKE_SOURCE_DIR}/src/config.h)

include_directories(/usr/include/botan-1.10)

aux_source_directory(./src SRC_LIST)

add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries(${PROJECT_NAME} botan-1.10)
