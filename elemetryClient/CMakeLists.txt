cmake_minimum_required(VERSION 3.10)
project(elemetryClient)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add source files
set(SOURCES
    elemetryClient.cpp
    utils/utils.cpp
    symbols/symbols.cpp
    callbacks/callbacks.cpp
)

# Add header files
set(HEADERS
    elemetry.h
    utils/utils.h
    symbols/symbols.h
    callbacks/callbacks.h
)

# Create executable
add_executable(elemetryClient ${SOURCES} ${HEADERS})

# Link against required libraries
target_link_libraries(elemetryClient
    dbghelp
    psapi
)

# Add Windows-specific libraries
if(WIN32)
    target_link_libraries(elemetryClient 
        shlwapi.lib
    )
endif() 