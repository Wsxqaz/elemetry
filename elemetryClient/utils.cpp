#include <Windows.h>
#include <string>
#include <iostream>
#include <filesystem>

#include "utils.h"

const char* SYSTEM32_PATH = "C:\\Windows\\System32\\";  // Path to system32 directory

// Function to check if a file exists
bool FileExists(const std::string& filePath) {
    return std::filesystem::exists(filePath);
}

// Function to get the path to ntoskrnl.exe
std::string GetNtoskrnlPath() {
    // First, check current directory
    if (FileExists("ntoskrnl.exe")) {
        return "ntoskrnl.exe";
    }

    // Then check System32
    std::string system32Path = SYSTEM32_PATH;
    std::string ntoskrnlSystem32 = system32Path + "ntoskrnl.exe";
    if (FileExists(ntoskrnlSystem32)) {
        return ntoskrnlSystem32;
    }

    // Try other possible kernel names in System32
    std::string ntkrnlmpSystem32 = system32Path + "ntkrnlmp.exe";
    if (FileExists(ntkrnlmpSystem32)) {
        return ntkrnlmpSystem32;
    }

    std::string ntkrnlpaSystem32 = system32Path + "ntkrnlpa.exe";
    if (FileExists(ntkrnlpaSystem32)) {
        return ntkrnlpaSystem32;
    }

    // Not found
    return "";
}

// Helper function to convert wstring to string
std::string wstring_to_string(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

