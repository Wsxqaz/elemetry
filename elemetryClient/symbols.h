#pragma once

#include <Windows.h>

extern const char* DEFAULT_SYMBOL_PATH;

// Primary symbol names for callback tables
extern const char* SYMBOL_LOAD_IMAGE_CALLBACKS;
extern const char* SYMBOL_PROCESS_CALLBACKS;
extern const char* SYMBOL_THREAD_CALLBACKS;
extern const char* SYMBOL_REGISTRY_CALLBACKS;

extern const char* ALT_REGISTRY_CALLBACKS[];
extern const int ALT_REGISTRY_COUNT;
extern const char* ALT_LOAD_IMAGE_CALLBACKS[];
extern const int ALT_LOAD_IMAGE_COUNT;
extern const char* ALT_PROCESS_CALLBACKS[];
extern const int ALT_PROCESS_COUNT;


extern bool TestSymbolLookup(HANDLE deviceHandle);
extern bool LoadKernelModuleSymbols(HANDLE deviceHandle);
extern size_t LookupSymbol(HANDLE deviceHandle, const char* symbolName, DWORD64& address);


