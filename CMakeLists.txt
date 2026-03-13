cmake_minimum_required(VERSION 3.15)
project(crowRESTmicroservice LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
find_package(OpenSSL REQUIRED)

include_directories(include SYSTEM /usr/include)

# API Binary
add_executable(crow_api src/main.cpp src/crypto_utils.cpp)
target_link_libraries(crow_api PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Test Binary
add_executable(unit_tests tests/test_main.cpp src/crypto_utils.cpp)
target_link_libraries(unit_tests PRIVATE OpenSSL::SSL OpenSSL::Crypto)
