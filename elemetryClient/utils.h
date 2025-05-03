#include <Windows.h>

extern const char* SYSTEM32_PATH;  // Path to system32 directory

extern std::string GetNtoskrnlPath();
extern bool FileExists(const std::string& path);
extern std::string wstring_to_string(const std::wstring& wstr);

