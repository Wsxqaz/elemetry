#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>

#include "elemetry.h"

// Function to open a handle to the driver device
HANDLE OpenDriverHandle() {
    HANDLE deviceHandle = CreateFileW(
        L"\\\\.\\elemetry",
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

// Function to print module information
void PrintModuleInfo(const MODULE_INFO& moduleInfo) {
    std::wcout << L"Module: " << moduleInfo.Path << std::endl;
    std::cout << "  Base Address: 0x" << std::hex << moduleInfo.BaseAddress << std::dec << std::endl;
    std::cout << "  Size: " << moduleInfo.Size << " bytes" << std::endl;
    std::cout << "  Flags: 0x" << std::hex << moduleInfo.Flags << std::dec << std::endl;
    std::cout << std::endl;
}

// Function to get callback type as string
std::string GetCallbackTypeString(CALLBACK_TYPE type) {
    switch (type) {
    case CALLBACK_TYPE::Unknown: return "Unknown";
    case CALLBACK_TYPE::PsLoadImage: return "PsLoadImage";
    case CALLBACK_TYPE::PsProcessCreation: return "PsProcessCreation";
    case CALLBACK_TYPE::PsThreadCreation: return "PsThreadCreation";
    case CALLBACK_TYPE::CmRegistry: return "CmRegistry";
    case CALLBACK_TYPE::ObProcessHandlePre: return "ObProcessHandlePre";
    case CALLBACK_TYPE::ObProcessHandlePost: return "ObProcessHandlePost";
    case CALLBACK_TYPE::ObThreadHandlePre: return "ObThreadHandlePre";
    case CALLBACK_TYPE::ObThreadHandlePost: return "ObThreadHandlePost";
    default: return "Unknown";
    }
}

// Function to print callback information
void PrintCallbackInfo(const CALLBACK_INFO_SHARED& callbackInfo) {
    std::cout << "Callback: " << callbackInfo.CallbackName << std::endl;
    std::cout << "  Type: " << GetCallbackTypeString(callbackInfo.Type) << std::endl;
    std::cout << "  Address: 0x" << std::hex << callbackInfo.Address << std::dec << std::endl;
    std::cout << "  Module: " << callbackInfo.ModuleName << std::endl;
    std::cout << "  Context: 0x" << std::hex << callbackInfo.Context << std::dec << std::endl;
    std::cout << std::endl;
}

// Function to get and display modules from the driver
bool GetDriverModules() {
    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Allocate buffer for module information
    const DWORD bufferSize = sizeof(MODULE_INFO) * MAX_MODULES;
    std::vector<BYTE> buffer(bufferSize, 0);
    PMODULE_INFO moduleInfos = reinterpret_cast<PMODULE_INFO>(buffer.data());

    // Send IOCTL to get module information
    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        deviceHandle,
        IOCTL_GET_MODULES,
        moduleInfos, bufferSize,
        moduleInfos, bufferSize,
        &bytesReturned,
        nullptr
    );

    if (!success) {
        std::cerr << "DeviceIoControl failed. Error code: " << GetLastError() << std::endl;
        CloseHandle(deviceHandle);
        return false;
    }

    // Calculate number of modules returned
    DWORD moduleCount = bytesReturned / sizeof(MODULE_INFO);
    std::cout << "Retrieved " << moduleCount << " modules:" << std::endl << std::endl;

    // Print module information
    for (DWORD i = 0; i < moduleCount; i++) {
        PrintModuleInfo(moduleInfos[i]);
    }

    CloseHandle(deviceHandle);
    return true;
}

// Function to get and display callbacks from the driver
bool GetDriverCallbacks() {
    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Allocate buffer for callback information
    const DWORD bufferSize = sizeof(CALLBACK_INFO_SHARED) * MAX_CALLBACKS;
    std::vector<BYTE> buffer(bufferSize, 0);
    PCALLBACK_INFO_SHARED callbackInfos = reinterpret_cast<PCALLBACK_INFO_SHARED>(buffer.data());

    // Send IOCTL to get callback information
    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        deviceHandle,
        IOCTL_GET_CALLBACKS,
        callbackInfos, bufferSize,
        callbackInfos, bufferSize,
        &bytesReturned,
        nullptr
    );

    if (!success) {
        std::cerr << "DeviceIoControl failed. Error code: " << GetLastError() << std::endl;
        CloseHandle(deviceHandle);
        return false;
    }

    // Calculate number of callbacks returned
    DWORD callbackCount = bytesReturned / sizeof(CALLBACK_INFO_SHARED);
    std::cout << "Retrieved " << callbackCount << " callbacks:" << std::endl << std::endl;

    // Print callback information
    for (DWORD i = 0; i < callbackCount; i++) {
        PrintCallbackInfo(callbackInfos[i]);
    }

    CloseHandle(deviceHandle);
    return true;
}

int main() {
    std::cout << "Elemetry Client - Driver Module and Callback Enumerator" << std::endl;
    std::cout << "========================================================" << std::endl << std::endl;

    std::cout << "Querying driver for modules..." << std::endl;
    if (!GetDriverModules()) {
        std::cerr << "Failed to get modules from driver." << std::endl;
        return 1;
    }

    std::cout << "Querying driver for callbacks..." << std::endl;
    if (!GetDriverCallbacks()) {
        std::cerr << "Failed to get callbacks from driver." << std::endl;
        return 1;
    }

    std::cout << "Operation completed successfully." << std::endl;
    return 0;
} 