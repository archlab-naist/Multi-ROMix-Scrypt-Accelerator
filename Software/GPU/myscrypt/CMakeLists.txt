# CMakeLists files in this project can
# refer to the root source directory of the project as ${HELLO_SOURCE_DIR} and
# to the root binary directory of the project as ${HELLO_BINARY_DIR}.
cmake_minimum_required (VERSION 3.8 FATAL_ERROR)
project (SCRYPT CUDA CXX)

# if(NOT DEFINED CMAKE_CXX_STANDARD)
#     set(CMAKE_CXX_STANDARD 11)
#     set(CMAKE_CXX_STANDARD_REQUIRED true)
# endif()
# if(NOT DEFINED CMAKE_CUDA_STANDARD)
#     set(CMAKE_CUDA_STANDARD 11)
#     set(CMAKE_CUDA_STANDARD_REQUIRED true)
# endif()

include_directories(include)
include_directories(${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES})
set(CMAKE_CUDA_STANDARD 14)
add_library(scrypt_lib STATIC
    # scrypt.h
    # sha256.h
    # utils.h
    # datatypes.h 
    src/scrypt.cpp 
    src/sha256.cpp 
    src/utils.cpp
  )
# Request that particles be built with -std=c++11
# As this is a public compile feature anything that links to 
# particles will also build with -std=c++11
target_compile_features(scrypt_lib PUBLIC cxx_std_11)

# We need to explicitly state that we need all CUDA files in the 
# particle library to be built with -dc as the member functions 
# could be called by other libraries and executables
set_target_properties( scrypt_lib
                       PROPERTIES CUDA_SEPARABLE_COMPILATION ON)
# set source choose the top file
set(SOURCES test/test_scrypt_gpu.cu)
add_executable(scrypt ${SOURCES})
set_property(TARGET scrypt 
                       PROPERTY CUDA_SEPARABLE_COMPILATION ON)

set(CMAKE_TRY_COMPILE_TARGET_TYPE "STATIC_LIBRARY")



# set(THREADS_PREFER_PTHREAD_FLAG ON)
# find_package(Threads REQUIRED)
# target_link_libraries(SCRYPT PRIVATE Threads::Threads)

target_link_libraries(scrypt PRIVATE scrypt_lib)

if(APPLE)
  # We need to add the path to the driver (libcuda.dylib) as an rpath, 
  # so that the static cuda runtime can find it at runtime.
  set_property(TARGET scrypt 
               PROPERTY
               BUILD_RPATH ${CMAKE_CUDA_IMPLICIT_LINK_DIRECTORIES})
endif()
