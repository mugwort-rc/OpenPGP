PROJECT(tests)

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${OpenPGP_SOURCE_DIRS}/cmake/Modules")
FIND_PACKAGE(GMPXX REQUIRED)

INCLUDE_DIRECTORIES(gtest-1.7.0 gtest-1.7.0/include)
INCLUDE_DIRECTORIES(${OpenPGP_INCLUDE_DIRS})

SET(exec_SRCS
gtest-1.7.0/src/gtest-all.cc
gtest-1.7.0/src/gtest_main.cc
testcases/test_aes128_ecb.cpp
testcases/test_aes192_ecb.cpp
testcases/test_aes256_ecb.cpp
testcases/test_blowfish_ecb.cpp
testcases/test_camellia_ecb.cpp
testcases/test_cast128_ecb.cpp
testcases/test_dsa.cpp
testcases/test_idea_ecb.cpp
testcases/test_md5.cpp
testcases/test_pgp.cpp
testcases/test_radix64.cpp
testcases/test_ripemd160.cpp
testcases/test_rsa.cpp
testcases/test_sha1.cpp
testcases/test_sha224.cpp
testcases/test_sha256.cpp
testcases/test_sha384.cpp
testcases/test_sha512.cpp
testcases/test_tripledes_ecb.cpp
testcases/test_twofish_ecb.cpp
)

ADD_EXECUTABLE(${PROJECT_NAME} ${exec_SRCS})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} OpenPGP ${GMPXX_LIBRARIES} ${GMP_LIBRARY} pthread)
