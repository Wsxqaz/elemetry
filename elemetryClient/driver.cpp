#include <Windows.h>
#include <iostream>

// Constants
const char* DRIVER_NAME = "\\\\.\\Elemetry"; // NT device path for our driver

// Function to open a handle to the driver device
HANDLE OpenDriverHandle() {
    HANDLE deviceHandle = CreateFileA(
        DRIVER_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (deviceHandle == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open device handle. Error code: " << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }

    return deviceHandle;
}

