project(libbitmessage)

cmake_minimum_required(VERSION 2.8)

set(LIBRARY_NAME ${PROJECT_NAME})
set(MAJOR_VERSION 0)
set(MINOR_VERSION 1)
set(PATCH_VERSION 0)
set(LIBRARY_VERSION ${MAJOR_VERSION}.${MINOR_VERSION}-${PATCH_VERSION})

set(CMAKE_CXX_FLAGS "-std=c++11 -g -Wall")

set (BM_DEBUG 1)
set(CMAKE_BUILD_TYPE Debug)

configure_file(${CMAKE_SOURCE_DIR}/config.h.cmake ${CMAKE_SOURCE_DIR}/src/config.h)

aux_source_directory(./src SRC_LIST)
add_executable(${PROJECT_NAME} ${SRC_LIST})

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake/Modules/)

#find_package(Botan REQUIRED)
#include_directories(${Botan_INCLUDE_DIRS})
#set(LIBS ${LIBS} ${Botan_LIBRARIES})
#target_link_libraries(${PROJECT_NAME} ${LIBS})

include_directories(/usr/local/include/botan-1.11)
target_link_libraries(${PROJECT_NAME} /usr/local/lib/libbotan-1.11.so)
#target_link_libraries(${PROJECT_NAME} botan-1.11)

# Google Performance Tools
target_link_libraries(${PROJECT_NAME} profiler)
