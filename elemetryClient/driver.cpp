#include <Windows.h>
#include <iostream>

// Constants
const char* DRIVER_NAME = "\\\\.\\Elemetry"; // NT device path for our driver

// Function to open a handle to the driver device
HANDLE OpenDriverHandle() {
    HANDLE hDevice = CreateFile(
        L"\\\\.\\elemetry",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        wchar_t errorMsg[256];
        swprintf_s(errorMsg, L"CreateFile failed with error: %d", error);
        MessageBox(NULL, errorMsg, L"Error", MB_ICONERROR);
    }

    return hDevice;
}

