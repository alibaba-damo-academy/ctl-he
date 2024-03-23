
# Minimum CMake version required to process this CMake file
cmake_minimum_required(VERSION 3.13)

# Name of the project
project(batchpbs)

# The type of build (e.g. Debug, Release, RelWithDebInfo, etc.)
set(CMAKE_BUILD_TYPE Debug)

# The directory where the compiled libraries will be stored
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# The directory where the compiled executables will be stored
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp")

# The C++ standard to be used for this project is C++17 and it's required
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)


# Adjust the way CMake's find_package function works. This determines the order in which versions of packages are found.
SET(CMAKE_FIND_PACKAGE_SORT_ORDER NATURAL)
SET(CMAKE_FIND_PACKAGE_SORT_DIRECTION DEC)

# Try to find and load settings from an external package (SEAL).
find_package(SEAL REQUIRED)
message(STATUS "Detected SEAL directory: ${SEAL_DIR}")
message(STATUS "SEAL_USE_INTEL_HEXL: ${SEAL_USE_INTEL_HEXL}")
message(STATUS "SEAL_USE_GAUSSIAN_NOISE: ${SEAL_USE_GAUSSIAN_NOISE}")

# Define the CXX flags to be used for compilation
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

# Check the compiler used. If it's GCC, it must be at least version 8.
# If it's not GCC, it must be Clang, otherwise, error out.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "8")
        message(FATAL_ERROR "Insufficient GCC version ${CMAKE_CXX_COMPILER_VERSION}")
    endif()
else(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    #using clang
    else(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "Unsupported CXX compiler ${CMAKE_CXX_COMPILER_ID}")
    endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
endif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")

# add google-test
# add_subdirectory(extern/googletest)
# include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})


# Include the src directory in the build process
add_subdirectory(src)


