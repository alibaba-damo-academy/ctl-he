
# Define the name of the target (library) to be built
set(TARGET_NAME batchpbs-crypto)

# List of source files to be compiled into the target
set(MODULE_FILES
    include/sealutil.h 
    include/cryptor.h 
    src/cryptor.cpp
    )

# Create a static library from the source files
add_library(${TARGET_NAME} STATIC ${MODULE_FILES})

# Specify the directories that the compiler will use to look for header files
target_include_directories(${TARGET_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Set compilation flags for this target
set_target_properties(${TARGET_NAME} PROPERTIES COMPILE_FLAGS "${CMAKE_CXX_FLAGS}")

# Link the target with the SEAL library
target_link_libraries(${TARGET_NAME} PUBLIC SEAL::seal)