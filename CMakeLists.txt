cmake_minimum_required(VERSION 3.23)

project(KsCrypto VERSION 1 LANGUAGES CXX C)

find_package(OpenSSL REQUIRED)
find_package(KsCMakeHelpers CONFIG REQUIRED)
find_package(KsLog CONFIG REQUIRED)
find_package(KsSerialization CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

ks_setup()

add_subdirectory(src)
add_subdirectory(include)

if(BUILD_TESTING)
  add_subdirectory(tests)
endif()
