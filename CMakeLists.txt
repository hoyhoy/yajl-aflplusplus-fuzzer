cmake_minimum_required(VERSION 4.4)
project(yajl_fuzzer LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(ENABLE_ASAN OFF CACHE INTERNAL "Build with ASan+UBSan+LSan")
set(ENABLE_CFISAN OFF CACHE INTERNAL "Build with CFISan")

set(CMAKE_BUILD_TYPE Debug)

set(CMAKE_C_FLAGS_DEBUG "-DDEBUG -g -glldb -O0 -gcolumn-info -fPIC -Wall")
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG -O3 -g -gcolumn-info -Wuninitialized")

set(YTP_NAME ytp CACHE STRING "Fuzzer executable name")

if (ENABLE_ASAN)
  set(asan_sanitize -fsanitize=address,undefined)
  set(asan_compile -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-common)
  if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
    list(APPEND asan_compile -fsanitize=leak -fsanitize=local-bounds)
  endif()
  if (CMAKE_C_COMPILER_ID MATCHES "Clang")
    list(APPEND asan_compile -fsanitize-address-use-after-scope
                             -fsanitize-address-use-after-return=always)
  endif()
  set(fuzz_compile ${asan_compile} ${asan_sanitize} -fsanitize=fuzzer)
  set(fuzz_link    ${asan_sanitize} -fsanitize=fuzzer)
elseif (ENABLE_CFISAN)
  if (NOT CMAKE_SYSTEM_NAME MATCHES "Linux" AND
      NOT CMAKE_SYSTEM_NAME MATCHES "FreeBSD" AND
      NOT CMAKE_SYSTEM_NAME MATCHES "NetBSD"
  )

  message(FATAL_ERROR "CFI Not Supported on ${CMAKE_SYSTEM_NAME}")
endif ()

  set(fuzz_compile -fno-omit-frame-pointer -fsanitize=cfi,fuzzer -flto -fvisibility=hidden -fno-sanitize=cfi-icall)
  set(fuzz_link    -fsanitize=cfi,fuzzer -flto -fvisibility=hidden)
endif()

find_package(YAJL 2 REQUIRED CONFIG)   # YAJL_DIR comes from the preset

add_executable(${YTP_NAME} yajl_tree_parse_fuzzer_enhanced.cpp)
target_link_libraries(${YTP_NAME} PRIVATE YAJL::yajl_s)
target_compile_options(${YTP_NAME} PRIVATE ${fuzz_compile})
target_link_options(${YTP_NAME} PRIVATE ${fuzz_link})

install(TARGETS ${YTP_NAME} RUNTIME DESTINATION bin)

add_executable(tc.${YTP_NAME} reproductions/test_crash.cpp)
target_link_libraries(tc.${YTP_NAME} PRIVATE YAJL::yajl_s)

