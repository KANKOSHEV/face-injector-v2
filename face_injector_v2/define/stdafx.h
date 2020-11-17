#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <fstream>
#include <regex>
#include <map>

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <shellapi.h>

#include <Windows.h>
#include <iostream>
#include <vector>
#include <memory>
#include <chrono>
#include <thread>
#include <mutex>	
#include <math.h>
#include <string>
#include <sstream>
#include <fstream>
#include <stdint.h>
#include <Shlobj.h>
#include <random>
#include <dwmapi.h>
#include <stdio.h>
#include <accctrl.h>
#include <aclapi.h>
#include <shlobj_core.h>
#include <locale>
#include <codecvt>
#include <thread>
#include <filesystem>
#include <array>
#include <Aclapi.h>
#include <sddl.h>
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Advapi32.lib")

using namespace std;
#define StrToWStr(s) (wstring(s, &s[strlen(s)]).c_str())
extern "C" NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

