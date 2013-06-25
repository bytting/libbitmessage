project(libbitmessage)

cmake_minimum_required(VERSION 2.8)

set(CMAKE_BUILD_TYPE Debug)

include_directories(/usr/include/botan-1.10)

aux_source_directory(./src SRC_LIST)

add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries(${PROJECT_NAME} botan-1.10)
#target_link_libraries(${PROJECT_NAME} crypto gmp)
