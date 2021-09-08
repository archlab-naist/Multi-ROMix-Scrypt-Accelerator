# CMakeLists files in this project can
# refer to the root source directory of the project as ${HELLO_SOURCE_DIR} and
# to the root binary directory of the project as ${HELLO_BINARY_DIR}.
cmake_minimum_required (VERSION 2.8.12)
project (SCRYPT)



# set(SOURCES src/sha256.cpp src/utils.cpp)
set(SOURCES test/test_scrypt_multithreads.cpp src/scrypt.cpp src/sha256.cpp src/utils.cpp)


include_directories(include)

add_executable(SCRYPT ${SOURCES})
target_link_libraries(SCRYPT pthread)

