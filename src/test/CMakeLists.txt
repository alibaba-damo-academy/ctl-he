
# Define the name of the target (library) to be built
set(TARGET_NAME batchpbs-test)

# List of source files to be compiled into the target
set(MODULE_FILES
    include/test_all.h 
    include/crypto_test.h 
    src/crypto_test.cpp
    )

# Create a static library from the source files
add_library(${TARGET_NAME} STATIC ${MODULE_FILES})

# Specify the directories that the compiler will use to look for header files
target_include_directories(${TARGET_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Set compilation flags for this target
set_target_properties(${TARGET_NAME} PROPERTIES COMPILE_FLAGS "${CMAKE_CXX_FLAGS}")

# Link the target with the batchpbs-crypto library
target_link_libraries(${TARGET_NAME} PRIVATE batchpbs-crypto)

# Define the name of the executable target to be built
set(TARGET_NAME test-all)

# Create an executable from the source file
enable_testing()
add_executable(${TARGET_NAME} src/test_all.cpp src/crypto_test.cpp)

# Link the executable with the batchpbs-crypto and batchpbs-test libraries
target_link_libraries(${TARGET_NAME} PRIVATE batchpbs-crypto batchpbs-test)