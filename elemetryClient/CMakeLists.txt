cmake_minimum_required(VERSION 3.10)
project(elemetryClient)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the executable
add_executable(elemetryClient elemetryClient.cpp)

# Add Windows-specific libraries
if(WIN32)
    target_link_libraries(elemetryClient 
        shlwapi.lib
    )
endif() 