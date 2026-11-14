cmake_minimum_required(VERSION 3.20)
project(yajl_fuzzer LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(YAJL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/yajl/build/yajl-2.1.1"
    CACHE PATH "Prebuilt yajl install prefix")

find_library(YAJL_S_LIBRARY yajl_s
  PATHS "${YAJL_ROOT}/lib"
  NO_DEFAULT_PATH
  REQUIRED)

add_library(yajl_s STATIC IMPORTED)
set_target_properties(yajl_s PROPERTIES
  IMPORTED_LOCATION "${YAJL_S_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${YAJL_ROOT}/include")

add_executable(fuzzer yajl_tree_parse_fuzzer.cpp)
target_link_libraries(fuzzer PRIVATE yajl_s)
